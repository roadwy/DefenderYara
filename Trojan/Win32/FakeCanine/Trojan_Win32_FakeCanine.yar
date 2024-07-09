
rule Trojan_Win32_FakeCanine{
	meta:
		description = "Trojan:Win32/FakeCanine,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_03_0 = {83 38 02 0f 85 ?? 00 00 00 68 ?? ?? 46 00 68 ?? ?? 46 00 e8 ?? ?? f9 ff 50 e8 ?? ?? f9 ff 80 38 e8 75 ?? 6a 34 } //3
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 47 75 61 72 64 44 6f 67 20 43 6f 6d 70 75 74 69 6e 67 } //1 Software\GuardDog Computing
		$a_01_2 = {61 6e 64 20 67 65 74 20 61 20 64 69 73 63 6f 75 6e 74 20 6f 66 20 32 30 24 2e } //1 and get a discount of 20$.
		$a_01_3 = {74 6f 20 61 76 6f 69 64 20 70 61 72 74 69 63 69 70 61 74 69 6e 67 20 69 6e 20 63 72 69 6d 69 6e 61 6c 20 61 63 74 69 76 69 74 79 2e } //1 to avoid participating in criminal activity.
		$a_01_4 = {59 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 63 61 6e 20 62 65 20 69 6e 66 65 63 74 65 64 2e 20 44 6f 20 79 6f 75 20 77 61 6e 74 } //1 Your computer can be infected. Do you want
		$a_01_5 = {73 65 65 6d 73 20 74 68 61 74 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 69 73 20 69 6e 66 65 63 74 65 64 20 77 69 74 68 20 57 33 32 3a 56 69 72 75 74 20 76 69 72 75 73 2e } //1 seems that your computer is infected with W32:Virut virus.
		$a_01_6 = {61 67 61 69 6e 73 74 20 69 64 65 6e 74 69 74 79 20 74 68 69 65 76 65 73 2c 20 67 72 61 62 62 65 72 73 2c 20 64 61 74 61 20 6d 69 6e 65 72 73 2c 20 65 74 63 2e } //1 against identity thieves, grabbers, data miners, etc.
		$a_01_7 = {73 63 61 6e 6e 69 6e 67 20 61 63 74 69 76 65 20 70 72 6f 63 65 73 73 65 73 20 65 76 65 72 79 20 73 65 63 6f 6e 64 20 61 6e 64 20 74 65 72 6d 69 6e 61 74 69 6e 67 20 73 75 73 70 } //1 scanning active processes every second and terminating susp
		$a_01_8 = {50 6f 73 73 69 62 6c 65 20 49 64 65 6e 74 69 74 79 20 54 68 65 66 74 20 44 65 74 65 63 74 65 64 21 } //1 Possible Identity Theft Detected!
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}