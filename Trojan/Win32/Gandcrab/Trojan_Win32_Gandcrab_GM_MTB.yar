
rule Trojan_Win32_Gandcrab_GM_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 c1 e8 05 03 45 90 01 01 8b cf c1 e1 04 03 4d 90 01 01 33 c1 8b 4d 90 01 01 81 45 fc 90 01 04 03 cf 33 c1 2b d8 ff 4d 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Gandcrab_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Gandcrab.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f be 18 e8 90 01 04 33 d8 8b 4d 90 01 01 03 4d 90 01 01 88 19 eb 90 09 14 00 8d 55 90 01 01 52 6a 90 01 01 6a 90 01 01 ff 15 90 01 04 8b 45 90 01 01 03 45 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}