
rule Backdoor_BAT_Androm_PSA_MTB{
	meta:
		description = "Backdoor:BAT/Androm.PSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 07 11 05 28 90 01 03 06 28 90 01 03 06 26 00 11 05 17 59 13 05 11 05 16 fe 04 16 fe 01 13 06 11 06 2d db 90 00 } //01 00 
		$a_01_1 = {74 72 61 6e 73 6d 69 73 73 69 6f 6e 4c 69 6e 65 31 5f 4c 6f 61 64 } //00 00  transmissionLine1_Load
	condition:
		any of ($a_*)
 
}