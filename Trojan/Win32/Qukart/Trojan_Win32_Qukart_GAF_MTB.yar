
rule Trojan_Win32_Qukart_GAF_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f8 29 f0 8b 55 08 8a 14 3a 88 94 05 90 01 04 47 39 df 7c 90 00 } //10
		$a_03_1 = {6a 00 6a 00 e8 90 01 04 89 f0 f7 e6 89 85 90 01 04 89 c6 8d 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=20
 
}