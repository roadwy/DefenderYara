
rule Trojan_Win32_Zusy_GJM_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 34 37 34 35 30 37 30 31 31 35 34 35 31 37 30 35 32 } //01 00  cdn.discordapp.com/attachments/947450701154517052
		$a_01_1 = {5c 79 75 6b 69 2d 6d 6f 64 75 6c 65 2e 64 6c 6c } //01 00  \yuki-module.dll
		$a_01_2 = {5c 64 6f 6e 74 5f 6c 6f 61 64 2e 74 78 74 } //01 00  \dont_load.txt
		$a_01_3 = {5c 69 6e 6a 65 63 74 5f 76 65 72 73 69 6f 6e 2e 74 78 74 } //01 00  \inject_version.txt
		$a_01_4 = {5c 6c 69 67 68 74 63 6f 72 64 2d 74 65 6d 70 5c 65 78 74 72 61 63 74 2e 65 78 65 } //00 00  \lightcord-temp\extract.exe
	condition:
		any of ($a_*)
 
}