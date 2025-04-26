
rule VirTool_BAT_Obfuscator_W{
	meta:
		description = "VirTool:BAT/Obfuscator.W,SIGNATURE_TYPE_PEHSTR,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 62 00 6c 00 6f 00 6f 00 64 00 63 00 72 00 79 00 70 00 74 00 2e 00 63 00 6f 00 6d 00 2f 00 69 00 6e 00 66 00 6f 00 2f 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //1 http://bloodcrypt.com/info/info.txt
		$a_01_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //1 Windows\CurrentVersion\Run
		$a_01_2 = {5c 00 76 00 32 00 2e 00 30 00 2e 00 35 00 30 00 37 00 32 00 37 00 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 } //1 \v2.0.50727\vbc.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}