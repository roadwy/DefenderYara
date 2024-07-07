
rule Trojan_Win32_Emotet_PX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b d0 8b 45 90 01 01 0f b6 14 10 8b 45 90 01 01 0f b6 0c 08 33 ca 90 00 } //1
		$a_03_1 = {2b c1 03 05 90 01 04 8b 55 90 01 01 2b c2 8b 4d 90 01 01 8b 55 90 01 01 88 14 01 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_PX_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 90 01 04 f7 f9 8b 44 24 90 01 01 40 89 44 24 90 01 01 8a 54 14 90 01 01 30 50 90 01 01 39 b4 24 90 01 04 90 01 06 8b 44 24 90 01 01 8b 8c 24 90 01 04 64 89 0d 90 01 04 59 5f 5e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}