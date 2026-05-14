
rule Trojan_BAT_Zusy_LRC_MTB{
	meta:
		description = "Trojan:BAT/Zusy.LRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 06 00 00 "
		
	strings :
		$a_01_0 = {7b 30 38 64 38 38 37 64 38 2d 65 62 62 33 2d 34 33 37 62 2d 61 34 63 61 2d 35 63 65 36 34 34 36 63 65 39 64 33 7d } //20 {08d887d8-ebb3-437b-a4ca-5ce6446ce9d3}
		$a_01_1 = {4d 65 6d 62 65 72 52 65 66 73 50 72 6f 78 79 } //15 MemberRefsProxy
		$a_01_2 = {43 72 65 61 74 65 4d 65 6d 62 65 72 52 65 66 73 44 65 6c 65 67 61 74 65 73 } //10 CreateMemberRefsDelegates
		$a_01_3 = {47 65 74 49 4c 47 65 6e 65 72 61 74 6f 72 } //8 GetILGenerator
		$a_01_4 = {4f 70 65 6e 43 6c 69 70 62 6f 61 72 64 } //5 OpenClipboard
		$a_01_5 = {47 6c 6f 62 61 6c 4c 6f 63 6b } //2 GlobalLock
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*8+(#a_01_4  & 1)*5+(#a_01_5  & 1)*2) >=60
 
}