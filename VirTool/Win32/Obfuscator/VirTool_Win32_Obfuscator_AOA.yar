
rule VirTool_Win32_Obfuscator_AOA{
	meta:
		description = "VirTool:Win32/Obfuscator.AOA,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 0f 4e 33 c1 } //1
		$a_01_1 = {ac 8b 0f 3a c8 75 07 40 47 48 75 f4 } //1
		$a_01_2 = {8b 48 3c 81 e1 ff ff 00 00 41 83 c0 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}