
rule Trojan_Win32_Ekstak_BE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c8 8d 14 30 8b 45 0c 8a 0c 31 88 0c 02 8a 8e 90 01 04 84 c9 75 90 01 01 8b 15 90 01 04 8a 0d 90 01 04 03 d6 03 c2 30 08 83 3d 90 01 04 03 76 90 00 } //1
		$a_02_1 = {89 03 8d 05 90 01 04 2b 30 83 e1 05 8a 82 90 01 04 84 c0 75 90 01 01 a1 90 01 04 8b 4d 0c 03 c2 03 c1 8a 0d 90 01 04 30 08 83 3d 90 01 04 03 7e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}