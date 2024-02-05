
rule Trojan_Win32_Qakbot_MK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {52 83 24 e4 90 01 01 31 3c e4 6a 00 89 3c e4 29 ff 0b 7d 08 89 fe 5f 53 33 1c e4 33 5f 90 01 01 83 e1 00 31 d9 5b 53 8b 5f 90 01 01 56 8f 45 f8 01 5d f8 ff 75 f8 5e 5b 8b 7f 0c 6a 00 01 2c e4 57 5d 03 ab 90 01 03 00 89 ef 5d f3 a4 81 e7 90 01 04 0b 3c e4 83 c4 90 01 01 50 89 f8 81 c0 90 01 04 89 c7 58 ff 4d fc 75 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}