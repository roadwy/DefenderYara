
rule Trojan_BAT_ProCheck_A_MSR{
	meta:
		description = "Trojan:BAT/ProCheck.A!MSR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 6f 66 69 6c 65 43 68 65 63 6b 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 50 72 6f 66 69 6c 65 43 68 65 63 6b 2e 70 64 62 } //1 ProfileCheck\obj\Release\ProfileCheck.pdb
		$a_01_1 = {42 61 74 63 68 42 75 69 6c 64 44 6f 63 6b 69 6e 67 50 61 6e 65 } //1 BatchBuildDockingPane
		$a_01_2 = {63 72 65 61 74 65 64 20 77 69 74 68 20 61 6e 20 65 76 61 6c 75 61 74 69 6f 6e 20 76 65 72 73 69 6f 6e 20 6f 66 20 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 } //1 created with an evaluation version of CryptoObfuscator
		$a_01_3 = {5f 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 24 00 } //1 _Encrypted$
		$a_01_4 = {55 00 48 00 4a 00 76 00 5a 00 6d 00 6c 00 73 00 5a 00 55 00 4e 00 6f 00 5a 00 57 00 4e 00 72 00 4a 00 41 00 3d 00 3d 00 } //1 UHJvZmlsZUNoZWNrJA==
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}