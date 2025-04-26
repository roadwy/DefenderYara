
rule Backdoor_Win32_Samcigap_A{
	meta:
		description = "Backdoor:Win32/Samcigap.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 46 68 60 ea 00 00 ff d7 46 81 fe 40 42 0f 00 7c ae } //3
		$a_00_1 = {25 73 6d 73 65 6e 73 65 25 64 2e 64 61 74 } //1 %smsense%d.dat
		$a_01_2 = {66 62 4d 75 73 74 45 78 69 74 4e 6f 77 00 } //1 扦畍瑳硅瑩潎w
		$a_01_3 = {4d 41 47 49 43 24 67 65 74 69 70 7e 00 } //1
		$a_00_4 = {67 65 74 69 6e 66 6f 2e 61 73 70 78 3f 61 3d 25 73 } //1 getinfo.aspx?a=%s
		$a_00_5 = {73 74 61 74 73 65 6e 64 2e 61 73 70 78 3f 61 3d 25 73 26 72 3d 25 64 26 } //1 statsend.aspx?a=%s&r=%d&
		$a_00_6 = {6e 73 74 61 72 74 2e 61 73 70 78 3f 61 3d 25 73 26 69 64 3d 25 73 } //1 nstart.aspx?a=%s&id=%s
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}