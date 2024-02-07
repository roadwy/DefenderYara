
rule TrojanSpy_AndroidOS_Banker_G_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.G!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {4c 6b 68 6a 6a 68 6b 67 68 6b 67 2f 79 75 6c 79 75 75 79 6b 6c 79 75 6b 79 2f } //02 00  Lkhjjhkghkg/yulyuuyklyuky/
		$a_00_1 = {65 72 79 65 72 79 65 72 79 65 72 79 65 72 2e 6a 61 76 61 } //01 00  eryeryeryeryer.java
		$a_00_2 = {52 75 6e 5f 4e 65 63 65 73 73 61 72 79 5f 49 6e 6a 65 63 74 69 6f 6e } //01 00  Run_Necessary_Injection
		$a_00_3 = {44 6f 77 6e 6c 6f 61 64 5f 41 6c 6c 5f 53 4d 53 } //01 00  Download_All_SMS
		$a_00_4 = {59 6f 75 72 20 70 68 6f 6e 65 20 68 61 73 20 62 65 65 6e 20 62 6c 6f 63 6b 65 64 } //01 00  Your phone has been blocked
		$a_00_5 = {55 72 67 65 6e 74 20 6d 65 73 73 61 67 65 21 } //00 00  Urgent message!
		$a_00_6 = {5d 04 00 00 } //c7 44 
	condition:
		any of ($a_*)
 
}