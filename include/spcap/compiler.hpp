/*
 * Copyright (c) 2017 Sergey Kovalevich <inndie@gmail.com>
 */

#ifndef KSERGEY_compiler_230117111318
#define KSERGEY_compiler_230117111318

#ifndef __packed
#   define __packed __attribute__((packed))
#endif

#ifndef __likely
#   define __likely(x) __builtin_expect(static_cast< bool >(x), true)
#endif

#ifndef __unlikely
#   define __unlikely(x) __builtin_expect(static_cast< bool >(x), false)
#endif

#endif /* KSERGEY_compiler_230117111318 */
