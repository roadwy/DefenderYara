
rule TrojanDownloader_O97M_EncDoc_VIA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 69 6e 69 2d 69 70 22 26 22 70 61 74 6d 61 6a 61 6c 65 6e 67 6b 61 2e 63 6f 6d 2f 39 64 76 38 38 36 48 57 43 2f 6c 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 "h"&"t"&"t"&"p"&"s://ini-ip"&"patmajalengka.com/9dv886HWC/l.h"&"t"&"m"&"l
		$a_01_1 = {22 68 22 26 22 74 74 22 26 22 70 22 26 22 73 3a 2f 2f 6d 65 72 77 65 64 64 69 6e 67 2e 63 6f 6d 2e 74 72 2f 76 63 6b 64 48 34 7a 72 31 2f 6c 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //1 "h"&"tt"&"p"&"s://merwedding.com.tr/vckdH4zr1/l.h"&"t"&"m"&"l"
		$a_01_2 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 70 22 26 22 72 65 73 22 26 22 74 69 67 65 6c 64 6e 73 65 72 76 69 63 65 73 2e 63 6f 2e 75 6b 2f 37 31 52 67 50 31 51 6f 4c 2f 6c 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //1 "h"&"t"&"t"&"ps://p"&"res"&"tigeldnservices.co.uk/71RgP1QoL/l.h"&"t"&"m"&"l"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_VIA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 65 22 26 22 6d 22 26 22 61 22 26 22 69 6c 2e 63 61 22 26 22 73 75 22 26 22 61 6c 73 22 26 22 74 72 65 65 74 2e 63 6f 6d 2e 62 72 2f 43 6a 6c 45 57 6d 36 45 2f 67 6f 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //1 "h"&"t"&"t"&"p"&"s://e"&"m"&"a"&"il.ca"&"su"&"als"&"treet.com.br/CjlEWm6E/go.h"&"t"&"m"&"l"
		$a_01_1 = {22 68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 61 22 26 22 75 22 26 22 74 6f 22 26 22 73 61 22 26 22 6c 64 65 22 26 22 74 61 6c 22 26 22 6c 65 2e 63 6f 6d 2e 61 72 2f 39 6c 22 26 22 32 45 22 26 22 7a 45 4b 22 26 22 30 6e 53 4c 77 2f 67 6f 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //1 "h"&"tt"&"ps://a"&"u"&"to"&"sa"&"lde"&"tal"&"le.com.ar/9l"&"2E"&"zEK"&"0nSLw/go.h"&"t"&"m"&"l"
		$a_01_2 = {22 68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 61 22 26 22 6c 75 22 26 22 6d 22 26 22 6e 69 2e 69 22 26 22 74 62 2e 61 63 2e 69 64 2f 4f 22 26 22 61 30 22 26 22 33 49 6a 22 26 22 50 37 22 26 22 66 45 2f 67 6f 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //1 "h"&"tt"&"ps://a"&"lu"&"m"&"ni.i"&"tb.ac.id/O"&"a0"&"3Ij"&"P7"&"fE/go.h"&"t"&"m"&"l"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}