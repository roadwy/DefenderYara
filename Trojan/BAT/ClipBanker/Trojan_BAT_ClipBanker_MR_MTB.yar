
rule Trojan_BAT_ClipBanker_MR_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {24 66 65 32 30 33 66 37 34 2d 66 65 37 39 2d 34 64 37 31 2d 38 65 63 62 2d 32 36 38 66 33 64 38 37 62 63 39 38 } //1 $fe203f74-fe79-4d71-8ecb-268f3d87bc98
		$a_81_1 = {57 69 6e 48 6f 73 74 2e 65 78 65 } //1 WinHost.exe
		$a_81_2 = {53 65 76 69 72 65 6d 2e 43 6c 69 70 70 65 72 } //1 Sevirem.Clipper
		$a_81_3 = {44 65 63 72 79 70 74 } //1 Decrypt
		$a_81_4 = {47 43 48 61 6e 64 6c 65 } //1 GCHandle
		$a_81_5 = {44 65 63 6f 6d 70 72 65 73 73 } //1 Decompress
		$a_81_6 = {52 75 6e 74 69 6d 65 46 69 65 6c 64 48 61 6e 64 6c 65 } //1 RuntimeFieldHandle
		$a_81_7 = {42 69 74 44 65 63 6f 64 65 72 } //1 BitDecoder
		$a_81_8 = {54 6f 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 ToBase64String
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}