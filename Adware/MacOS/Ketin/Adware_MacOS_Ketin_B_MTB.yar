
rule Adware_MacOS_Ketin_B_MTB{
	meta:
		description = "Adware:MacOS/Ketin.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 5f 73 79 73 63 74 6c 00 5f 73 79 73 63 74 6c 62 79 6e 61 6d 65 00 5f 73 79 73 74 65 6d 00 64 79 6c 64 5f 73 74 75 62 5f 62 69 6e 64 65 72 00 72 61 64 72 3a 2f 2f 35 36 31 34 35 34 32 } //01 00  开祳捳汴开祳捳汴祢慮敭开祳瑳浥搀汹彤瑳扵扟湩敤r慲牤⼺㔯ㄶ㔴㈴
		$a_00_1 = {75 72 6c 66 6f 72 61 70 70 6c 69 63 61 74 69 6f 6e 74 6f 6f 70 65 6e 75 72 6c } //01 00  urlforapplicationtoopenurl
		$a_00_2 = {6f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d 56 65 72 73 69 6f 6e } //00 00  operatingSystemVersion
	condition:
		any of ($a_*)
 
}