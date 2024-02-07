
rule Backdoor_BAT_Bladabindi_AA_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d 44 b9 ff ff ff } //03 00 
		$a_81_1 = {53 69 6d 70 6c 65 44 65 74 65 63 74 6f 72 } //03 00  SimpleDetector
		$a_81_2 = {53 79 73 74 65 6d 2e 4e 65 74 2e 4e 65 74 77 6f 72 6b 49 6e 66 6f 72 6d 61 74 69 6f 6e } //03 00  System.Net.NetworkInformation
		$a_81_3 = {52 53 41 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //00 00  RSACryptoServiceProvider
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Bladabindi_AA_MTB_2{
	meta:
		description = "Backdoor:BAT/Bladabindi.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 6f 76 69 64 2e 65 78 65 } //01 00  Covid.exe
		$a_81_1 = {49 6e 6a 65 63 74 69 6f 6e 5f 44 6f 57 6f 72 6b } //01 00  Injection_DoWork
		$a_81_2 = {68 61 63 6b 69 6e 67 20 74 6f 6f 6c } //01 00  hacking tool
		$a_81_3 = {53 65 65 20 47 68 6f 73 74 73 20 43 68 61 74 } //01 00  See Ghosts Chat
		$a_81_4 = {35 35 20 38 42 20 45 43 20 38 30 20 33 44 20 30 35 20 36 31 20 42 43 20 36 33 20 30 30 } //01 00  55 8B EC 80 3D 05 61 BC 63 00
		$a_81_5 = {68 74 74 70 73 3a 2f 2f 68 61 73 74 65 62 69 6e 2e 63 6f 6d 2f 72 61 77 2f 6d 61 72 75 7a 75 63 65 68 69 } //01 00  https://hastebin.com/raw/maruzucehi
		$a_81_6 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 75 73 74 61 62 66 2e 74 6b 2f 75 70 64 61 74 65 2e 74 78 74 } //00 00  http://www.gustabf.tk/update.txt
		$a_00_7 = {5d 04 00 00 } //8d 4c 
	condition:
		any of ($a_*)
 
}