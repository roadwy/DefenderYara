
rule Trojan_Win32_IcedId_DAU_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {53 6a 01 53 53 8d 44 24 ?? 50 89 5c 24 ?? ff 15 ?? ?? ?? ?? 85 c0 75 ?? 6a 08 6a 01 53 53 8d 4c 24 90 1b 00 51 ff 15 90 1b 02 85 c0 } //1
		$a_81_1 = {6a 7a 61 57 6d 76 55 34 4e 78 77 68 4f 58 51 } //1 jzaWmvU4NxwhOXQ
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}