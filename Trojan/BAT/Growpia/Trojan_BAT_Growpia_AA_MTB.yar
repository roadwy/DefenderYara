
rule Trojan_BAT_Growpia_AA_MTB{
	meta:
		description = "Trojan:BAT/Growpia.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_81_0 = {73 63 72 65 65 6e 73 68 6f 74 2e 70 6e 67 } //01 00  screenshot.png
		$a_81_1 = {63 72 65 64 65 6e 74 69 61 6c 73 2e 74 78 74 } //01 00  credentials.txt
		$a_81_2 = {70 77 64 2e 74 78 74 } //01 00  pwd.txt
		$a_81_3 = {67 65 74 5f 57 65 62 48 6f 6f 6b } //01 00  get_WebHook
		$a_81_4 = {50 61 73 74 65 53 74 65 61 6c 65 72 } //01 00  PasteStealer
		$a_81_5 = {42 72 75 74 65 66 6f 72 63 65 48 61 63 6b } //01 00  BruteforceHack
		$a_81_6 = {5c 41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 47 72 6f 77 74 6f 70 69 61 } //01 00  \AppData\Local\Growtopia
		$a_81_7 = {65 63 68 6f 20 6a 20 7c 20 64 65 6c 20 54 72 69 6e 69 74 79 2e 62 61 74 } //01 00  echo j | del Trinity.bat
		$a_81_8 = {5c 41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 53 65 72 76 69 63 65 73 2e 65 78 65 } //00 00  \AppData\Roaming\Services.exe
	condition:
		any of ($a_*)
 
}