
rule Trojan_Win32_Johnnie_PA_MTB{
	meta:
		description = "Trojan:Win32/Johnnie.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b ce c1 f9 1f 8b d1 33 c8 33 d7 3b ca 7f 90 01 01 8b 4d 90 01 01 8b 09 8b 51 0c 8b 79 14 2b d7 8a c8 80 e1 90 01 01 8d 3c 02 8a 14 02 32 ca 32 cb 03 c6 88 0f eb 90 00 } //1
		$a_02_1 = {8b ce c1 f9 1f 8b d1 33 c8 33 d7 3b ca 7f 90 01 01 8b 4d 90 01 01 8b 09 8b 51 0c 8b 79 14 2b d7 8a 0c 02 8d 3c 02 32 c8 32 cb 03 c6 88 0f eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}