
rule VirTool_Win32_Obfuscator_PN_Alureon{
	meta:
		description = "VirTool:Win32/Obfuscator.PN!Alureon,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {5f 47 69 76 65 54 68 69 73 54 6f 54 68 61 74 4d 61 6e 40 31 32 } //1 _GiveThisToThatMan@12
	condition:
		((#a_01_0  & 1)*1) >=1
 
}