
rule TrojanDropper_BAT_Bepush_C{
	meta:
		description = "TrojanDropper:BAT/Bepush.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 53 45 78 74 65 6e 73 69 6f 6e } //\SExtension  01 00 
		$a_80_1 = {59 6f 6b 45 78 65 2e 65 78 65 } //YokExe.exe  01 00 
		$a_80_2 = {2f 65 78 74 46 69 6c 65 73 2f 63 6f 6e 74 72 6f 6c } ///extFiles/control  00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_BAT_Bepush_C_2{
	meta:
		description = "TrojanDropper:BAT/Bepush.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {5c 56 45 78 74 65 6e 73 69 6f 6e } //\VExtension  01 00 
		$a_80_1 = {59 6f 6b 45 78 65 2e 65 78 65 } //YokExe.exe  01 00 
		$a_80_2 = {2f 65 78 74 46 69 6c 65 73 2f 63 6f 6e 74 72 6f 6c } ///extFiles/control  00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDropper_BAT_Bepush_C_3{
	meta:
		description = "TrojanDropper:BAT/Bepush.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_80_0 = {46 6c 61 73 68 20 55 70 64 61 74 65 } //Flash Update  01 00 
		$a_80_1 = {5c 53 45 78 74 65 6e 73 69 6f 6e } //\SExtension  01 00 
		$a_80_2 = {59 6f 6b 45 78 65 2e 65 78 65 } //YokExe.exe  01 00 
		$a_80_3 = {46 61 63 65 62 6f 6f 6b } //Facebook  00 00 
	condition:
		any of ($a_*)
 
}