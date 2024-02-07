
rule Backdoor_BAT_Gantorpe_A{
	meta:
		description = "Backdoor:BAT/Gantorpe.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 6e 69 71 75 65 20 42 6f 74 2e 65 78 65 } //01 00  Unique Bot.exe
		$a_02_1 = {55 6e 69 71 75 65 20 42 6f 74 90 02 08 4d 69 63 72 6f 73 6f 66 74 90 02 08 43 6f 70 79 72 69 67 68 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}