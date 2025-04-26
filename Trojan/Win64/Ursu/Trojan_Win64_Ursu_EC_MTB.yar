
rule Trojan_Win64_Ursu_EC_MTB{
	meta:
		description = "Trojan:Win64/Ursu.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {70 74 41 38 49 35 46 59 36 51 53 36 2d 6d 50 67 } //1 ptA8I5FY6QS6-mPg
		$a_81_1 = {38 5f 39 6a 2f 35 53 72 49 48 52 54 56 4b 61 61 78 4f 74 37 6f 69 30 50 5a 2f 4f 31 48 35 7a 4b } //1 8_9j/5SrIHRTVKaaxOt7oi0PZ/O1H5zK
		$a_81_2 = {56 4d 36 74 4d 73 52 50 73 77 } //1 VM6tMsRPsw
		$a_81_3 = {6d 34 2f 75 5f 59 54 30 77 48 31 4b 77 79 38 4c 6f 54 } //1 m4/u_YT0wH1Kwy8LoT
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}