
rule PWS_Win32_Wowsteal_AE{
	meta:
		description = "PWS:Win32/Wowsteal.AE,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {79 69 6c 75 37 37 37 } //4 yilu777
		$a_00_1 = {2f 73 78 78 78 2f 7a 68 2f 67 65 74 2e 61 73 70 } //3 /sxxx/zh/get.asp
		$a_00_2 = {25 73 3f 75 73 3d 25 73 26 70 73 3d } //2 %s?us=%s&ps=
		$a_00_3 = {25 73 5c 25 73 00 00 00 73 76 63 68 6f 73 74 2e 65 78 65 } //2
		$a_01_4 = {77 74 66 5c 63 6f 6e 66 69 67 2e 77 74 66 } //1 wtf\config.wtf
		$a_01_5 = {77 6f 77 73 79 73 74 65 6d 63 6f 64 65 } //1 wowsystemcode
		$a_01_6 = {6c 6f 67 6f 6e 2e 77 6f 72 6c 64 6f 66 77 61 72 63 72 61 66 74 2e 63 6f 6d } //1 logon.worldofwarcraft.com
	condition:
		((#a_00_0  & 1)*4+(#a_00_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}