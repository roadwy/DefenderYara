
rule Trojan_Win32_Zenpak_AMCY_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMCY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 8b 5c 24 20 55 8b 6c 24 20 57 55 ff 15 ?? ?? ?? ?? 53 8b f8 66 c7 44 24 14 02 00 ff 15 } //4
		$a_03_1 = {6a 10 8b 08 8d 44 24 ?? 50 8b 11 8b 4e 08 51 89 54 24 ?? ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}