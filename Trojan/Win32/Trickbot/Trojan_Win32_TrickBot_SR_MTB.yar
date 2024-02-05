
rule Trojan_Win32_TrickBot_SR_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {89 ce 83 e6 03 75 90 01 01 8b 5d 10 66 01 da 6b d2 02 c1 ca 03 89 55 10 30 10 40 e2 90 01 01 c9 90 00 } //01 00 
		$a_02_1 = {83 7d f8 01 7e 90 01 01 8b 4d f8 0f b6 91 90 01 04 03 15 90 01 04 8b 45 f8 88 90 01 05 8b 0d 90 01 04 8b 15 90 01 04 8d 44 0a a1 a3 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}