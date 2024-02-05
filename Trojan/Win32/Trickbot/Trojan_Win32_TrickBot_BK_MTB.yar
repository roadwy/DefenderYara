
rule Trojan_Win32_TrickBot_BK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c2 99 b9 40 34 01 00 f7 f9 8b 45 90 01 01 33 c9 8a 0c 10 89 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f be 02 50 8b 4d 90 01 01 51 e8 90 01 04 83 c4 08 8b 55 90 01 01 03 55 90 01 01 88 02 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}