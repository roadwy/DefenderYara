
rule VirTool_Win32_Obfuscator_ADZ{
	meta:
		description = "VirTool:Win32/Obfuscator.ADZ,SIGNATURE_TYPE_PEHSTR,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 07 65 57 b0 81 fa 6b 08 7b 5d b5 0d d5 f6 d6 ca 31 e6 60 eb ea 3f d7 6c 36 b8 52 de ed 21 c6 8a 76 37 cc ce 90 8c 69 d5 91 3a a3 ef 4e 54 ad } //1
		$a_01_1 = {6f 25 2b 30 ba 93 ec 98 bd 47 d8 bd 88 36 f3 1b f4 45 ef 35 c4 62 8a 3f f1 39 60 4b 9a 2b 46 1e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}