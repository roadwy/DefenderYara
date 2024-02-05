
rule Trojan_Win32_Razy_V_MTB{
	meta:
		description = "Trojan:Win32/Razy.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 4a 03 32 8a 90 01 04 32 cb 88 8a 90 01 04 42 83 fa 90 01 01 7c e9 90 00 } //01 00 
		$a_02_1 = {8d 41 03 32 81 90 01 04 32 c2 88 81 90 01 04 41 83 f9 90 01 01 7c e9 90 00 } //01 00 
		$a_02_2 = {8d 41 03 32 c2 30 81 90 01 04 41 83 f9 90 01 01 7c ef 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}