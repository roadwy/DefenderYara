
rule Trojan_Win32_Qakbot_ZW{
	meta:
		description = "Trojan:Win32/Qakbot.ZW,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //05 00 
		$a_01_1 = {0f af 81 44 06 00 00 } //05 00 
		$a_01_2 = {f6 80 98 18 00 00 82 } //01 00 
		$a_00_3 = {5d 04 00 00 c4 00 05 80 5c 21 } //00 00 
	condition:
		any of ($a_*)
 
}