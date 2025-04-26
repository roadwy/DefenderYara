
rule VirTool_BAT_Obfuscator_Devpoint{
	meta:
		description = "VirTool:BAT/Obfuscator.Devpoint,SIGNATURE_TYPE_PEHSTR_EXT,64 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 72 2e 48 61 63 6b 65 72 73 20 44 5a 20 44 45 56 2d 50 4f 49 4e 54 2e 73 6e 6b } //1 Mr.Hackers DZ DEV-POINT.snk
	condition:
		((#a_01_0  & 1)*1) >=1
 
}