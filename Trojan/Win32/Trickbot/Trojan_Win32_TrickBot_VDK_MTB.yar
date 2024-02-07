
rule Trojan_Win32_TrickBot_VDK_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.VDK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {67 30 35 64 37 6b 36 67 57 46 64 33 68 79 74 50 50 6f 77 45 } //02 00  g05d7k6gWFd3hytPPowE
		$a_01_1 = {66 73 49 31 7a 6f 46 6b 50 34 38 73 43 69 6f 67 36 53 6f 7a } //02 00  fsI1zoFkP48sCiog6Soz
		$a_01_2 = {67 35 47 30 78 63 4a 4d 38 4a 48 76 78 70 74 56 4a 67 79 79 6e 69 } //02 00  g5G0xcJM8JHvxptVJgyyni
		$a_01_3 = {68 46 4b 76 6e 64 74 6f 50 4d 67 68 33 4f 4e 4f 6b 5a 51 42 56 45 57 33 } //02 00  hFKvndtoPMgh3ONOkZQBVEW3
		$a_01_4 = {68 51 58 6b 34 76 70 76 48 64 6a 7a 6e 69 4b 55 6b 30 48 75 6e 76 75 38 } //02 00  hQXk4vpvHdjzniKUk0Hunvu8
		$a_01_5 = {68 6e 34 36 59 61 67 61 4d 36 78 49 46 56 52 6a 33 5a 65 72 5a 62 77 6c } //02 00  hn46YagaM6xIFVRj3ZerZbwl
		$a_01_6 = {68 6d 50 42 78 64 57 58 35 33 64 54 74 4a 41 6e 4f 51 67 54 46 65 34 51 6a } //00 00  hmPBxdWX53dTtJAnOQgTFe4Qj
	condition:
		any of ($a_*)
 
}