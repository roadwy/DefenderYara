
rule Backdoor_BAT_Nanocore_GG_MTB{
	meta:
		description = "Backdoor:BAT/Nanocore.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {4e 61 6e 6f 43 6f 72 65 2e 43 6c 69 65 6e 74 50 6c 75 67 69 6e } //NanoCore.ClientPlugin  01 00 
		$a_80_1 = {4d 79 43 6c 69 65 6e 74 50 6c 75 67 69 6e 2e 64 6c 6c } //MyClientPlugin.dll  01 00 
		$a_80_2 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 4e 61 6e 6f 43 6f 72 65 53 77 69 73 73 5c 4d 79 43 6c 69 65 6e 74 50 6c 75 67 69 6e 5c 6f 62 6a 5c 44 65 62 75 67 5c 4d 79 43 6c 69 65 6e 74 50 6c 75 67 69 6e 2e 70 64 62 } //\Downloads\NanoCoreSwiss\MyClientPlugin\obj\Debug\MyClientPlugin.pdb  00 00 
	condition:
		any of ($a_*)
 
}