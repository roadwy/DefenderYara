
rule Trojan_Win32_Emotet_PVB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 90 01 04 f7 f9 8b 45 90 01 01 8a 4c 15 00 30 08 90 09 04 00 0f b6 4d 90 00 } //1
		$a_81_1 = {4a 55 66 64 48 38 5a 51 43 59 7a 76 70 55 34 72 56 63 61 48 56 72 43 63 70 73 79 62 62 4b 43 75 } //1 JUfdH8ZQCYzvpU4rVcaHVrCcpsybbKCu
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}