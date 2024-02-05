
rule Backdoor_BAT_LoaderCsharp_A{
	meta:
		description = "Backdoor:BAT/LoaderCsharp.A,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_00_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 72 00 65 00 67 00 69 00 73 00 74 00 65 00 72 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 69 00 6e 00 66 00 6f 00 2e 00 63 00 6f 00 6d 00 2f 00 66 00 61 00 76 00 69 00 63 00 6f 00 6e 00 2e 00 69 00 63 00 6f 00 } //0a 00 
		$a_01_1 = {5c 4c 6f 61 64 65 72 43 73 68 61 72 70 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 43 73 68 61 72 70 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}