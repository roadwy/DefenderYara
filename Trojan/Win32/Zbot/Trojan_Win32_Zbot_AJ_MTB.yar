
rule Trojan_Win32_Zbot_AJ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {47 73 40 00 46 00 01 01 63 73 40 00 43 00 01 01 83 73 40 00 44 00 01 01 9f } //3
		$a_01_1 = {74 67 74 71 66 } //2 tgtqf
		$a_01_2 = {69 78 73 64 } //2 ixsd
		$a_01_3 = {6d 78 73 76 77 70 } //2 mxsvwp
		$a_01_4 = {69 6c 6f 62 71 74 } //2 ilobqt
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=7
 
}