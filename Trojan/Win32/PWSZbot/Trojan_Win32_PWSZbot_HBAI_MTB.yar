
rule Trojan_Win32_PWSZbot_HBAI_MTB{
	meta:
		description = "Trojan:Win32/PWSZbot.HBAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {52 21 52 d7 30 64 98 24 4a b8 69 03 21 32 89 ff 43 2e f1 75 a9 } //0a 00 
		$a_01_1 = {a3 05 17 8c 0a 08 c2 31 f1 29 fe 41 47 } //01 00 
		$a_01_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00  URLDownloadToFile
		$a_01_3 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00  ShellExecute
	condition:
		any of ($a_*)
 
}