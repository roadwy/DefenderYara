
rule Trojan_Win32_Bandit_DSK_MTB{
	meta:
		description = "Trojan:Win32/Bandit.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {e8 ef ff ff c7 05 90 01 04 be d3 85 d0 90 00 } //01 00 
		$a_00_1 = {80 e3 c0 08 9d ea ef ff ff } //01 00 
		$a_02_2 = {e9 05 00 00 0f 84 90 01 06 80 e2 fc c0 e2 04 08 95 e9 ef ff ff 83 90 01 01 2c 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}