
rule Backdoor_AndroidOS_Basdoor_C_MTB{
	meta:
		description = "Backdoor:AndroidOS/Basdoor.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 65 73 75 6c 74 3d 6f 6b 26 61 63 74 69 6f 6e 3d 6e 77 6d 65 73 73 61 67 65 26 61 6e 64 72 6f 69 64 69 64 3d } //1 result=ok&action=nwmessage&androidid=
		$a_00_1 = {72 65 73 75 6c 74 3d 6f 6b 26 61 63 74 69 6f 6e 3d 70 69 6e 67 26 61 6e 64 72 6f 69 64 69 64 3d } //1 result=ok&action=ping&androidid=
		$a_00_2 = {7e 74 65 73 74 2e 74 65 73 74 } //1 ~test.test
		$a_00_3 = {53 65 6e 64 53 69 6e 67 6c 65 4d 65 73 73 61 67 65 } //1 SendSingleMessage
		$a_00_4 = {68 69 64 65 69 63 6f 6e } //1 hideicon
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}