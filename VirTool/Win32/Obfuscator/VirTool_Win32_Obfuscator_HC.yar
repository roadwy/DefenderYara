
rule VirTool_Win32_Obfuscator_HC{
	meta:
		description = "VirTool:Win32/Obfuscator.HC,SIGNATURE_TYPE_PEHSTR,0a 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 cd 2e eb 08 58 2d c4 2e eb 08 eb f4 86 e0 91 0f c9 81 e9 4c d9 01 00 03 ca eb 02 cc e9 ff d1 34 35 83 e0 0f } //00 00 
	condition:
		any of ($a_*)
 
}