
rule VirTool_BAT_CryptInject_BA_MTB{
	meta:
		description = "VirTool:BAT/CryptInject.BA!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 00 61 00 7a 00 66 00 75 00 73 00 63 00 61 00 74 00 6f 00 72 00 2e 00 4e 00 45 00 54 00 } //1 Eazfuscator.NET
		$a_01_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 47 00 61 00 70 00 6f 00 74 00 63 00 68 00 65 00 6e 00 6b 00 6f 00 5c 00 } //1 Software\Gapotchenko\
		$a_01_2 = {53 70 6f 74 69 66 79 20 43 68 65 63 6b 65 72 2e 65 78 65 } //1 Spotify Checker.exe
		$a_01_3 = {43 00 6f 00 6d 00 62 00 6f 00 2e 00 74 00 78 00 74 00 } //1 Combo.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}