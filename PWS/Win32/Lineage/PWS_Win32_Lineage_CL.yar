
rule PWS_Win32_Lineage_CL{
	meta:
		description = "PWS:Win32/Lineage.CL,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 00 4a 75 6d 70 48 6f 6f 6b 4f 66 66 00 4a 75 6d 70 48 6f 6f 6b 4f 6e } //1 汄啬牮来獩整卲牥敶r畊灭潈歯晏f畊灭潈歯湏
		$a_01_1 = {65 31 78 70 32 6c 6f 72 65 33 72 } //1 e1xp2lore3r
		$a_01_2 = {41 63 63 65 70 74 2d 4c 61 6e 67 75 61 67 65 3a 20 7a 68 2d 63 6e } //1 Accept-Language: zh-cn
		$a_01_3 = {55 73 65 72 2d 41 67 65 6e 74 3a 20 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } //1 User-Agent: Mozilla/4.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}