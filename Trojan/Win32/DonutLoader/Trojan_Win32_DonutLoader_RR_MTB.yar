
rule Trojan_Win32_DonutLoader_RR_MTB{
	meta:
		description = "Trojan:Win32/DonutLoader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 19 c1 c7 0f c1 c0 0d 83 c1 04 31 f8 c1 ea 0a 89 df 31 d0 89 da c1 c7 0e 03 41 1c c1 ca 07 31 fa 89 df c1 ef 03 31 fa 01 d0 89 f2 8b 74 24 50 01 c6 8d 84 24 24 01 00 00 89 71 38 39 c8 75 } //1
		$a_01_1 = {0f b6 08 0f b6 50 01 83 c7 01 83 c0 04 30 54 24 70 32 58 fe 31 ce 88 58 1e 89 f1 88 48 1c 0f b6 4c 24 70 88 48 1d 0f b6 48 ff 30 4c 24 60 0f b6 4c 24 60 88 48 1f 83 ff 3c } //1
		$a_01_2 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 } //1 DllGetClassObject
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}