
rule Worm_Win32_Autorun_ACN{
	meta:
		description = "Worm:Win32/Autorun.ACN,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 41 75 74 6f 72 75 6e 2e 69 6e 66 } //02 00  \Autorun.inf
		$a_01_1 = {25 73 20 56 69 72 55 73 20 22 22 20 22 6c 6f 6c 22 20 3a 25 73 } //01 00  %s VirUs "" "lol" :%s
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 49 4d 20 25 73 } //01 00  taskkill /IM %s
		$a_01_3 = {25 73 5c 72 65 6d 6f 76 65 4d 65 25 69 25 69 25 69 25 69 2e 62 61 74 } //01 00  %s\removeMe%i%i%i%i.bat
		$a_01_4 = {50 52 49 56 4d 53 47 } //00 00  PRIVMSG
	condition:
		any of ($a_*)
 
}