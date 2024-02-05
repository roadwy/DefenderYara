
rule Trojan_Win32_Qakbot_U{
	meta:
		description = "Trojan:Win32/Qakbot.U,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //0a 00 
		$a_03_1 = {08 01 00 00 32 90 01 02 04 88 90 01 03 3b 90 01 01 72 e8 90 0a 1a 00 76 18 8b 90 01 01 83 90 01 01 03 8a 90 00 } //01 00 
		$a_00_2 = {5d 04 00 00 21 91 04 80 5c 24 } //00 00 
	condition:
		any of ($a_*)
 
}