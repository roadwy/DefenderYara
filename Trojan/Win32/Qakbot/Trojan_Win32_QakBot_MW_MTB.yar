
rule Trojan_Win32_QakBot_MW_MTB{
	meta:
		description = "Trojan:Win32/QakBot.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {85 c0 74 3b 8b 90 02 03 3b 90 02 05 72 02 eb 2e 8b 90 02 03 03 90 02 03 8b 90 02 03 03 90 02 03 68 90 02 04 ff 90 02 05 03 90 02 03 8b 90 02 03 8a 90 02 03 88 90 02 03 8b 90 02 03 83 90 02 03 89 90 02 03 eb 90 00 } //01 00 
		$a_02_1 = {89 11 33 c0 e9 90 0a 28 00 a1 90 02 04 c7 05 90 02 08 01 05 90 02 06 8b 0d 90 02 04 8b 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}