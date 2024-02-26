
rule Trojan_BAT_PureLogsStealer_APL_MTB{
	meta:
		description = "Trojan:BAT/PureLogsStealer.APL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f 90 01 01 00 00 0a 00 25 16 6f 90 01 01 00 00 0a 00 0c 08 6f 90 01 01 00 00 0a 72 90 01 01 05 00 70 6f 90 01 01 00 00 0a 26 08 6f 90 00 } //01 00 
		$a_01_1 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 6f 72 61 72 79 20 50 72 6f 6a 65 63 74 73 5c 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 31 5c 6f 62 6a 5c 44 65 62 75 67 5c 69 54 61 6c 6b 2e 70 64 62 } //00 00  \AppData\Local\Temporary Projects\WindowsFormsApp1\obj\Debug\iTalk.pdb
	condition:
		any of ($a_*)
 
}