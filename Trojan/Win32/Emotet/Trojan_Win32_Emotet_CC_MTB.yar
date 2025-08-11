
rule Trojan_Win32_Emotet_CC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_81_0 = {23 4c 36 62 4f 59 4f 3e 49 55 32 3e 63 53 34 32 47 49 59 75 46 79 4a 44 26 47 32 49 63 24 4a 43 2b 44 5e 6d 4d 36 4a 6d 39 62 76 63 31 44 63 4b 36 } //3 #L6bOYO>IU2>cS42GIYuFyJD&G2Ic$JC+D^mM6Jm9bvc1DcK6
		$a_81_1 = {43 72 65 61 74 65 53 74 64 41 63 63 65 73 73 69 62 6c 65 4f 62 6a 65 63 74 } //3 CreateStdAccessibleObject
		$a_81_2 = {4e 6f 52 65 63 65 6e 74 44 6f 63 73 48 69 73 74 6f 72 79 } //3 NoRecentDocsHistory
		$a_81_3 = {46 69 6e 64 52 65 73 6f 75 72 63 65 41 } //3 FindResourceA
		$a_81_4 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //3 LoadResource
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3+(#a_81_4  & 1)*3) >=15
 
}