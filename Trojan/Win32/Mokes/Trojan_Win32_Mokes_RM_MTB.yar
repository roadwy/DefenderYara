
rule Trojan_Win32_Mokes_RM_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 f6 85 ff 7e 90 01 01 81 ff 85 02 00 00 75 90 01 01 6a 00 ff 15 90 01 04 8b 44 24 90 01 01 8d 0c 06 e8 90 01 04 30 01 46 3b f7 7c 90 00 } //01 00 
		$a_02_1 = {c1 ea 05 c7 05 90 01 04 84 10 d6 cb c7 05 90 01 04 ff ff ff ff 89 54 24 90 01 01 8b 84 24 90 01 04 01 44 24 90 01 01 8b 44 24 90 01 01 8b 4c 24 90 01 01 33 c6 33 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}