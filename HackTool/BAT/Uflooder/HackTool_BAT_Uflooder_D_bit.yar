
rule HackTool_BAT_Uflooder_D_bit{
	meta:
		description = "HackTool:BAT/Uflooder.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {54 00 43 00 50 00 20 00 66 00 6c 00 6f 00 6f 00 64 00 } //01 00  TCP flood
		$a_01_1 = {55 00 44 00 50 00 20 00 66 00 6c 00 6f 00 6f 00 64 00 } //01 00  UDP flood
		$a_01_2 = {53 00 74 00 6f 00 70 00 70 00 65 00 64 00 20 00 61 00 6c 00 6c 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 73 00 } //01 00  Stopped all attacks
		$a_01_3 = {53 00 65 00 6e 00 64 00 69 00 6e 00 67 00 20 00 43 00 6f 00 6e 00 68 00 6f 00 6c 00 64 00 20 00 66 00 6c 00 6f 00 6f 00 64 00 } //01 00  Sending Conhold flood
		$a_01_4 = {61 00 74 00 74 00 61 00 63 00 6b 00 73 00 20 00 61 00 72 00 65 00 20 00 63 00 75 00 72 00 72 00 65 00 6e 00 74 00 6c 00 79 00 20 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 } //01 00  attacks are currently running
		$a_01_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //00 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_6 = {5d 04 00 } //00 de 
	condition:
		any of ($a_*)
 
}