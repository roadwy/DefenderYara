
rule VirTool_Win32_Obfuscator_CAJ{
	meta:
		description = "VirTool:Win32/Obfuscator.CAJ,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 54 89 1d 90 01 04 8f 05 90 01 04 8f 05 90 01 04 a1 90 01 04 89 35 90 01 04 89 3d 90 01 04 ff e0 cc 0f 0b 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}