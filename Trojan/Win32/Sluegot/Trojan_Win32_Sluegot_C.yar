
rule Trojan_Win32_Sluegot_C{
	meta:
		description = "Trojan:Win32/Sluegot.C,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 65 74 75 73 67 6f } //2 letusgo
		$a_00_1 = {25 73 3f 72 61 6e 64 73 3d 25 73 26 61 63 63 3d 25 73 26 73 74 72 3d 25 73 } //2 %s?rands=%s&acc=%s&str=%s
		$a_00_2 = {72 75 6e 66 69 6c 65 } //1 runfile
		$a_00_3 = {64 6f 77 6e 66 69 6c 65 } //1 downfile
		$a_00_4 = {6b 69 6c 6c 70 } //1 killp
		$a_00_5 = {6d 65 73 73 61 67 65 70 69 65 63 65 6c 65 6e 67 74 68 3a 25 73 } //1 messagepiecelength:%s
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}