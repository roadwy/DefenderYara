
rule Trojan_Win32_QakBot_G_MTB{
	meta:
		description = "Trojan:Win32/QakBot.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {88 f0 f6 e2 8b 75 90 01 01 8b 7d 90 01 01 8a 14 3e 88 45 90 01 01 80 f6 90 01 01 88 75 90 01 01 2b 4d 90 01 01 8b 5d 90 01 01 88 14 3b 01 cf 8b 4d 90 01 01 39 cf 89 7d 90 01 01 75 90 09 10 00 8b 45 90 01 01 b9 90 01 04 b2 90 01 01 8a 75 90 01 01 89 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}