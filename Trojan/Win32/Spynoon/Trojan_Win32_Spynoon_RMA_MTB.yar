
rule Trojan_Win32_Spynoon_RMA_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 f6 1d 7e c4 b0 f7 de 81 c6 41 6b 9a 64 3b 73 90 01 01 0f 95 c1 89 8d 90 01 04 8d b5 90 01 04 8b 0e 03 4f 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Spynoon_RMA_MTB_2{
	meta:
		description = "Trojan:Win32/Spynoon.RMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0d 00 ff ff ff 40 89 45 90 01 01 8b 45 90 01 01 0f b6 84 05 90 01 04 8b 4d 90 01 01 03 4d 90 01 01 0f b6 09 33 c8 8b 45 90 01 01 03 45 90 01 01 88 08 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}