
rule Trojan_Win64_AsyncRAT_ARA_MTB{
	meta:
		description = "Trojan:Win64/AsyncRAT.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {4b 44 46 36 32 44 46 4a 46 4a 46 46 32 36 4a 2e 62 61 74 } //02 00  KDF62DFJFJFF26J.bat
		$a_01_1 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 69 6d 20 73 76 63 68 6f 73 74 2e 65 78 65 } //03 00  taskkill /F /im svchost.exe
		$a_01_2 = {5c 44 69 73 63 6f 72 64 4e 75 6b 65 42 6f 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 31 2e 70 64 62 } //03 00  \DiscordNukeBot\x64\Release\1.pdb
		$a_01_3 = {5c 73 68 61 72 65 73 63 72 65 65 6e 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 73 68 61 72 65 73 63 72 65 65 6e 2e 70 64 62 } //00 00  \sharescreen\x64\Release\sharescreen.pdb
	condition:
		any of ($a_*)
 
}