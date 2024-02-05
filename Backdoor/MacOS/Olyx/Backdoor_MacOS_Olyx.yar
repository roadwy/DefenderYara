
rule Backdoor_MacOS_Olyx{
	meta:
		description = "Backdoor:MacOS/Olyx,SIGNATURE_TYPE_MACHOHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2f 55 73 65 72 73 2f 79 78 6c 2f 44 6f 63 75 6d 65 6e 74 73 2f 58 63 6f 64 65 2f 6d 61 63 70 61 6b 2f 6d 61 69 6e 2e 63 } //02 00 
		$a_00_1 = {2f 74 6d 70 2f 67 6f 6f 67 6c 65 2e 74 6d 70 } //02 00 
		$a_00_2 = {2f 4c 69 62 72 61 72 79 2f 4c 61 75 6e 63 68 41 67 65 6e 74 73 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 74 73 74 61 72 74 2e 70 6c 69 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}