
rule Trojan_Win32_Zbot_DAZ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {05 80 f9 27 75 03 8a 90 01 04 10 57 89 01 eb 25 84 d2 74 0a 0f be 08 0f b6 fa 3b cf eb 90 00 } //01 00 
		$a_01_1 = {2b c6 33 c9 85 c0 0f 9f c1 f7 d8 1b c0 8d 4c 09 ff 23 c1 5f 5e 5b 5d c3 } //00 00 
	condition:
		any of ($a_*)
 
}