
rule Trojan_Win32_ZexaF_NF_MTB{
	meta:
		description = "Trojan:Win32/ZexaF.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 85 98 fa ff ff 89 06 8a 85 ?? ?? ff ff 88 46 04 8d 85 ?? ?? ff ff 50 ff b5 ?? ?? ff ff 6a 05 56 57 } //3
		$a_03_1 = {ff ff 50 8d 45 c0 66 c7 45 d0 22 00 50 8d 85 ?? ?? ff ff 50 0f } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}