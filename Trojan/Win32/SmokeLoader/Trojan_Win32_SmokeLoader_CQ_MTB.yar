
rule Trojan_Win32_SmokeLoader_CQ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 18 8b 44 24 18 89 44 24 1c 8b f7 c1 ee 05 03 f5 8b 44 24 1c 31 44 24 10 81 3d [0-04] 21 01 00 00 75 } //2
		$a_03_1 = {8b 4c 24 10 33 ce 8d 44 24 24 89 4c 24 10 e8 [0-04] 81 44 24 20 47 86 c8 61 83 6c 24 2c 01 0f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}