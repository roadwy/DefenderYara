
rule Trojan_Win32_Qakbot_SAQ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f6 3a db 74 90 01 01 bb 90 01 04 03 e3 bb 90 01 04 e9 90 01 04 8b 45 90 01 01 0f b6 44 10 90 01 01 33 c8 66 90 01 02 74 90 00 } //01 00 
		$a_00_1 = {57 69 6e 64 } //01 00 
		$a_00_2 = {55 54 5f 53 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}