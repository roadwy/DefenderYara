
rule PWS_Win32_Rugond_A{
	meta:
		description = "PWS:Win32/Rugond.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 00 6c 00 6c 00 5c 00 61 00 67 00 65 00 6e 00 74 00 52 00 65 00 70 00 6c 00 79 00 2e 00 76 00 62 00 70 00 } //01 00  dll\agentReply.vbp
		$a_01_1 = {43 00 61 00 72 00 64 00 55 00 73 00 65 00 2e 00 61 00 73 00 70 00 78 00 3f 00 61 00 63 00 74 00 69 00 6f 00 6e 00 3d 00 63 00 68 00 6f 00 6e 00 67 00 7a 00 68 00 69 00 26 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 3d 00 } //01 00  CardUse.aspx?action=chongzhi&username=
		$a_01_2 = {73 00 75 00 2e 00 6d 00 69 00 63 00 72 00 6f 00 72 00 75 00 69 00 2e 00 63 00 6f 00 6d 00 2f 00 } //01 00  su.microrui.com/
		$a_01_3 = {4d 00 69 00 63 00 72 00 6f 00 53 00 75 00 2e 00 6c 00 6f 00 67 00 } //01 00  MicroSu.log
		$a_01_4 = {51 45 6c 65 6d 65 6e 74 43 6c 69 65 6e 74 20 57 69 6e 64 6f 77 } //01 00  QElementClient Window
		$a_01_5 = {77 6c 7a 68 75 7a 68 75 2e 63 6f 6d 2f 6b 73 72 65 67 5f 73 65 72 76 65 72 2f 75 70 6c 6f 67 73 2e 70 68 70 3f 73 6f 66 74 63 6f 64 65 3d } //00 00  wlzhuzhu.com/ksreg_server/uplogs.php?softcode=
	condition:
		any of ($a_*)
 
}