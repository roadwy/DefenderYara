
rule Trojan_BAT_AsyncRAT_MVB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MVB!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 6d 70 74 79 43 6c 65 61 6e 2e 65 78 65 } //2 EmptyClean.exe
		$a_01_1 = {57 72 69 74 65 4c 69 6e 65 } //1 WriteLine
		$a_01_2 = {4d 44 35 44 65 63 72 79 70 74 } //1 MD5Decrypt
		$a_01_3 = {65 65 34 30 66 30 65 62 2d 37 66 63 31 2d 34 64 61 64 2d 61 63 31 66 2d 31 63 63 61 38 66 38 37 30 32 66 64 } //1 ee40f0eb-7fc1-4dad-ac1f-1cca8f8702fd
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}