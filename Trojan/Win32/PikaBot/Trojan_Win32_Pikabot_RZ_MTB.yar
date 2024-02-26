
rule Trojan_Win32_Pikabot_RZ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.RZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 dc 03 45 e4 e9 } //01 00 
		$a_01_1 = {f7 f6 8b 45 f8 eb } //01 00 
		$a_01_2 = {0f b6 44 10 10 33 c8 eb } //01 00 
		$a_01_3 = {45 78 63 70 74 } //00 00  Excpt
	condition:
		any of ($a_*)
 
}