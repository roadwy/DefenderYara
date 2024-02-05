
rule VirTool_BAT_Obfuscator_BD{
	meta:
		description = "VirTool:BAT/Obfuscator.BD,SIGNATURE_TYPE_PEHSTR,64 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 09 03 09 91 04 09 04 8e b7 5d 91 61 08 09 08 8e b7 5d 91 61 9c 00 09 17 d6 0d } //00 00 
	condition:
		any of ($a_*)
 
}