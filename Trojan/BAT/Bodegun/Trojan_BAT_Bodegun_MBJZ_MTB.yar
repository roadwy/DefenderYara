
rule Trojan_BAT_Bodegun_MBJZ_MTB{
	meta:
		description = "Trojan:BAT/Bodegun.MBJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 09 17 20 00 10 00 00 6f 90 01 01 00 00 0a fe 01 13 10 11 10 2c b9 90 00 } //01 00 
		$a_01_1 = {65 66 2d 37 37 62 32 2d 34 33 31 66 2d 39 33 65 30 2d 66 33 31 33 64 34 38 66 65 63 34 65 } //01 00  ef-77b2-431f-93e0-f313d48fec4e
		$a_01_2 = {76 69 72 75 73 74 68 69 6e 67 32 2e 65 78 65 } //00 00  virusthing2.exe
	condition:
		any of ($a_*)
 
}