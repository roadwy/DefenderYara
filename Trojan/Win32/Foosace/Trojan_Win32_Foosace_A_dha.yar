
rule Trojan_Win32_Foosace_A_dha{
	meta:
		description = "Trojan:Win32/Foosace.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_09_0 = {2f 7e 25 73 2f 63 67 69 2d 62 69 6e 2f 25 73 2e 63 67 69 3f 25 73 } //2 /~%s/cgi-bin/%s.cgi?%s
		$a_09_1 = {62 72 76 63 00 73 70 74 72 00 71 66 61 00 6d 70 6b 00 } //2 牢捶猀瑰r晱a灭k
		$a_09_2 = {64 6c 6c 3a 25 2e 38 78 00 69 6e 73 3a 25 2e 38 78 00 } //2 汤㩬⸥砸椀獮┺㠮x
		$a_88_3 = {6d 73 6d 76 73 2e 65 78 65 00 } //1
		$a_88_4 = {6e 65 74 75 69 2e 64 6c 6c 00 } //1
	condition:
		((#a_09_0  & 1)*2+(#a_09_1  & 1)*2+(#a_09_2  & 1)*2+(#a_88_3  & 1)*1+(#a_88_4  & 1)*1) >=8
 
}