
rule Trojan_Win64_CobaltStrike_MM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 53 75 64 53 6f 6c 76 65 72 2e 70 64 62 } //5 \SudSolver.pdb
		$a_01_1 = {43 00 61 00 70 00 74 00 75 00 72 00 65 00 20 00 64 00 65 00 76 00 69 00 63 00 65 00 20 00 69 00 6e 00 66 00 6f 00 } //1 Capture device info
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_Win64_CobaltStrike_MM_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.MM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {f0 00 23 00 0b 02 0e 1d 00 c0 08 00 00 c0 97 } //5
		$a_01_1 = {ff 74 24 30 9d 48 8d 64 24 58 e8 53 92 7d 02 96 64 87 bd 01 9e e0 19 d8 81 e7 2b 86 03 eb 3c ad e1 f3 38 4f 6a 37 04 d7 b8 59 f4 bd 22 3c 71 40 } //2
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}