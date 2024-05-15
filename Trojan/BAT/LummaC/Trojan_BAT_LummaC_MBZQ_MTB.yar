
rule Trojan_BAT_LummaC_MBZQ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MBZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 03 00 "
		
	strings :
		$a_03_0 = {0b 07 1f 20 8d 1e 00 00 01 25 d0 ce 00 00 04 28 90 01 01 00 00 0a 6f 8f 00 00 0a 07 1f 10 90 00 } //02 00 
		$a_01_1 = {52 75 6e 6e 69 6e 67 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 } //02 00 
		$a_01_2 = {67 42 4d 74 68 65 70 6f 5a 53 4c 31 5a 56 4b 70 65 41 00 55 77 56 75 71 4c 6c 4c 4a 76 70 72 41 6f 53 33 66 63 00 50 51 } //01 00  䉧瑍敨潰博ㅌ噚灋䅥唀噷煵汌䩌灶䅲卯昳c児
		$a_01_3 = {41 6e 67 65 6c 6f } //01 00  Angelo
		$a_01_4 = {43 6f 72 72 65 63 74 } //01 00  Correct
		$a_01_5 = {52 65 6d 6f 74 65 4f 62 6a 65 63 74 73 } //00 00  RemoteObjects
	condition:
		any of ($a_*)
 
}