
rule Trojan_Win32_Zusy_KKO_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KKO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,26 00 26 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b d0 83 e2 0f 8a 92 cc 41 40 00 88 13 4b c1 e8 04 } //20
		$a_01_1 = {20 2d 3e 54 68 69 73 20 52 75 6e 20 54 69 6d 65 } //10  ->This Run Time
		$a_01_2 = {65 6f 21 23 66 69 72 73 74 64 61 74 65 74 69 6d 65 } //5 eo!#firstdatetime
		$a_01_3 = {72 75 6e 74 69 6d 65 73 2e 74 78 74 } //3 runtimes.txt
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3) >=38
 
}