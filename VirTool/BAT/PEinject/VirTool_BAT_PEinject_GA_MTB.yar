
rule VirTool_BAT_PEinject_GA_MTB{
	meta:
		description = "VirTool:BAT/PEinject.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 03 00 00 14 00 "
		
	strings :
		$a_00_0 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 } //0a 00  C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe
		$a_00_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 67 00 69 00 74 00 68 00 75 00 62 00 2e 00 63 00 6f 00 6d 00 2f 00 47 00 61 00 67 00 61 00 6e 00 69 00 6e 00 31 00 32 00 31 00 32 00 2f 00 62 00 75 00 67 00 74 00 69 00 6b 00 2f 00 72 00 61 00 77 00 2f 00 6d 00 61 00 69 00 6e 00 2f 00 } //0a 00  https://github.com/Gaganin1212/bugtik/raw/main/
		$a_80_2 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 47 61 67 61 6e 69 6e 31 32 31 32 2f 73 6f 73 61 6c 6b 61 2f 72 61 77 2f 6d 61 69 6e 2f } //https://github.com/Gaganin1212/sosalka/raw/main/  00 00 
	condition:
		any of ($a_*)
 
}