
rule Trojan_Win32_Zbot_CP_MTB{
	meta:
		description = "Trojan:Win32/Zbot.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {ac 34 31 11 10 10 d6 94 34 30 11 10 10 10 e3 bb } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}