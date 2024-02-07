
rule Trojan_BAT_AgentTesla_NWX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NWX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 11 06 06 11 06 9a 1f 10 28 90 01 03 0a 9c 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d de 90 00 } //01 00 
		$a_01_1 = {24 61 61 61 63 31 36 37 39 2d 31 65 36 63 2d 34 37 65 62 2d 61 33 32 36 2d 33 39 39 30 35 66 63 37 35 62 33 33 } //01 00  $aaac1679-1e6c-47eb-a326-39905fc75b33
		$a_01_2 = {24 31 65 32 65 33 38 62 37 2d 33 33 63 62 2d 34 33 38 34 2d 38 38 35 63 2d 31 65 31 31 63 63 62 64 32 31 34 34 } //00 00  $1e2e38b7-33cb-4384-885c-1e11ccbd2144
	condition:
		any of ($a_*)
 
}