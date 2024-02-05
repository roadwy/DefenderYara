
rule Backdoor_BAT_DCRat_GA_MTB{
	meta:
		description = "Backdoor:BAT/DCRat.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 0d 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 43 52 61 74 } //05 00 
		$a_80_1 = {44 43 52 61 74 2e 43 6f 64 65 } //DCRat.Code  01 00 
		$a_80_2 = {43 61 6d 65 72 61 } //Camera  01 00 
		$a_80_3 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d } //SELECT * FROM  01 00 
		$a_80_4 = {41 6e 74 69 76 69 72 75 73 } //Antivirus  01 00 
		$a_80_5 = {73 63 68 74 61 73 6b 73 } //schtasks  01 00 
		$a_80_6 = {57 65 62 63 61 6d } //Webcam  01 00 
		$a_80_7 = {73 74 65 61 6c 65 72 } //stealer  01 00 
		$a_80_8 = {62 72 6f 77 73 65 72 } //browser  01 00 
		$a_80_9 = {44 69 73 63 6f 72 64 } //Discord  01 00 
		$a_80_10 = {53 63 72 65 65 6e 73 68 6f 74 } //Screenshot  01 00 
		$a_80_11 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 46 69 72 65 77 61 6c 6c 50 72 6f 64 75 63 74 } //SELECT * FROM FirewallProduct  01 00 
		$a_80_12 = {64 70 6c 75 67 69 6e } //dplugin  00 00 
	condition:
		any of ($a_*)
 
}