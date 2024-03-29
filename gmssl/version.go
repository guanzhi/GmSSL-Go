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
#include <gmssl/version.h>
*/
import "C"

func GetVersions() []string {
	versions := []string {
		"GmSSL Go API 2.0",
		C.GoString(C.gmssl_version_str()),
	}
	return versions
}
