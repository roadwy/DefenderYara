
rule Trojan_Win64_Vidar_CCFX_MTB{
	meta:
		description = "Trojan:Win64/Vidar.CCFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b 49 64 41 03 89 90 01 04 41 8b 91 90 01 04 81 f1 90 01 04 0f af c1 81 c2 90 01 04 41 89 41 0c 41 03 51 40 41 8b 81 90 01 04 0f af c2 41 89 81 90 01 04 49 81 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}