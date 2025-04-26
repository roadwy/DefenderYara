
rule Trojan_Win32_Androm_AN_MTB{
	meta:
		description = "Trojan:Win32/Androm.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 89 85 02 ff ff ff ba ?? ?? ?? ?? 66 89 95 00 ff ff ff b8 ?? ?? ?? ?? 6b c8 00 8b 55 88 8b 42 0c 8b 0c 01 8b 11 89 95 04 ff ff ff 6a ?? 8d 85 00 ff ff ff 50 8b 4d ec 51 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}