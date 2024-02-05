
rule Trojan_Win32_Gandcrab_SGC_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.SGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b cf c1 e1 90 01 01 03 8d 90 01 01 90 01 03 33 c1 8b 8d 90 01 01 90 1b 02 03 cf 33 c1 2b d8 90 0a 35 00 c1 e8 90 01 01 03 85 90 01 01 90 1b 02 90 00 } //01 00 
		$a_02_1 = {8b c3 c1 e8 90 01 01 03 85 90 01 01 90 01 03 8b cb c1 e1 90 01 01 03 8d 90 01 01 90 1b 02 33 c1 8b 8d 90 01 01 90 1b 02 03 cb 33 c1 2b f8 90 0a 42 00 8b bd 90 01 01 90 1b 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}