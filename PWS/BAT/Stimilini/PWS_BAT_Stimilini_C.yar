
rule PWS_BAT_Stimilini_C{
	meta:
		description = "PWS:BAT/Stimilini.C,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 67 65 74 5f 75 6d 71 75 69 64 00 } //1 最瑥畟煭極d
		$a_01_1 = {00 73 65 74 5f 75 6d 71 75 69 64 00 } //1 猀瑥畟煭極d
		$a_01_2 = {00 67 65 74 5f 73 74 65 61 6d 49 44 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule PWS_BAT_Stimilini_C_2{
	meta:
		description = "PWS:BAT/Stimilini.C,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 73 74 65 61 6d 49 44 } //5 get_steamID
		$a_01_1 = {67 65 74 5f 66 72 69 65 6e 64 73 43 6f 75 6e 74 } //1 get_friendsCount
		$a_01_2 = {67 65 74 5f 75 6e 69 78 74 69 6d 65 73 74 61 6d 70 } //1 get_unixtimestamp
		$a_01_3 = {73 65 74 5f 73 65 73 73 69 6f 6e 49 44 } //1 set_sessionID
		$a_01_4 = {73 65 74 5f 75 6d 71 75 69 64 } //1 set_umquid
		$a_01_5 = {67 65 74 5f 61 63 63 65 73 73 5f 74 6f 6b 65 6e } //1 get_access_token
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}