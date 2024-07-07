
rule VirTool_Win32_Obfuscator_AID{
	meta:
		description = "VirTool:Win32/Obfuscator.AID,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 5d 01 45 32 d9 88 5c 38 02 40 3b c6 7c 90 01 01 85 ff c6 07 4d c6 47 01 5a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}