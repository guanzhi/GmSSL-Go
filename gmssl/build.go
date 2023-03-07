/*
 *  Copyright 2014-2023 The GmSSL Project. All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the License); you may
 *  not use this file except in compliance with the License.
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 */
/* +build cgo */

package gmssl

/*
#cgo darwin CFLAGS: -I/usr/local/include
#cgo darwin LDFLAGS: -L/usr/local/lib -lgmssl

*/
import "C"
