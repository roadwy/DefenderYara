
rule VirTool_Win32_Obfuscator_GB{
	meta:
		description = "VirTool:Win32/Obfuscator.GB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {ba fc fd fe ff } //01 00 
		$a_01_1 = {b8 f8 f9 fa fb } //01 00 
		$a_01_2 = {bb f4 f5 f6 f7 } //01 00 
		$a_01_3 = {bf f0 f1 f2 f3 } //01 00 
		$a_01_4 = {2d 10 10 10 10 81 eb 10 10 10 10 81 ea 10 10 10 10 } //02 00 
		$a_01_5 = {fe c2 30 07 fe c9 75 cd } //02 00 
		$a_01_6 = {ff 0c 24 ff 0c 24 81 2c 24 29 e7 97 00 ff 0c 24 58 } //00 00 
	condition:
		any of ($a_*)
 
}