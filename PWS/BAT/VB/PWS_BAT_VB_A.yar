
rule PWS_BAT_VB_A{
	meta:
		description = "PWS:BAT/VB.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 6f 74 6d 61 69 6c 5f 48 61 63 6b 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Hotmail_Hacker.My.Resources
		$a_00_1 = {49 00 73 00 20 00 61 00 74 00 74 00 65 00 6d 00 70 00 74 00 69 00 6e 00 67 00 20 00 74 00 6f 00 20 00 68 00 61 00 63 00 6b 00 3a 00 } //01 00  Is attempting to hack:
		$a_00_2 = {2a 00 2a 00 2a 00 59 00 6f 00 75 00 20 00 4d 00 55 00 53 00 54 00 20 00 42 00 65 00 20 00 4c 00 6f 00 67 00 67 00 65 00 64 00 20 00 49 00 6e 00 20 00 46 00 6f 00 72 00 20 00 54 00 68 00 69 00 73 00 20 00 54 00 6f 00 20 00 57 00 6f 00 72 00 6b 00 2a 00 2a 00 2a 00 } //00 00  ***You MUST Be Logged In For This To Work***
	condition:
		any of ($a_*)
 
}