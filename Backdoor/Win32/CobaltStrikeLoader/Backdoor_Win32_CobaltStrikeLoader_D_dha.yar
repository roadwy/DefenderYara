
rule Backdoor_Win32_CobaltStrikeLoader_D_dha{
	meta:
		description = "Backdoor:Win32/CobaltStrikeLoader.D!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 6d 69 3a 20 70 72 6f 62 61 6c 79 20 72 75 6e 6e 69 6e 67 20 6f 6e 20 73 61 6e 64 62 6f 78 } //01 00  wmi: probaly running on sandbox
		$a_01_1 = {73 70 61 77 6e 3a 3a 64 65 63 72 79 70 74 69 6e 67 2e 2e 2e } //01 00  spawn::decrypting...
		$a_01_2 = {5c 72 65 67 65 64 69 74 2e 65 78 65 } //00 00  \regedit.exe
	condition:
		any of ($a_*)
 
}