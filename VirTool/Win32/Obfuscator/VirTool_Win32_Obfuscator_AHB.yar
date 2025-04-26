
rule VirTool_Win32_Obfuscator_AHB{
	meta:
		description = "VirTool:Win32/Obfuscator.AHB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {54 52 41 53 48 5f 4c [0-05] 28 64 77 54 65 6d 70 31 2c 20 64 77 31 2c 20 64 77 32 29 3b 0d 0a 0d 0a 09 72 65 74 75 72 6e 3b 0d 0a 7d 0d 0a 0d 0a 23 65 6e 64 69 66 0d 0a 0d 0a 23 65 6c 73 65 0d 0a 76 6f 69 64 20 4f 62 66 75 73 63 61 74 69 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}