
rule Trojan_BAT_AgentTesla_NEO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 73 62 68 75 5f 41 64 6d 54 6d 70 6c 61 72 74 } //2 usbhu_AdmTmplart
		$a_01_1 = {73 6d 74 70 62 44 41 56 5f 6d 6f 76 65 } //2 smtpbDAV_move
		$a_01_2 = {44 44 41 73 6f 66 74 5f 42 75 69 4c 36 30 30 } //2 DDAsoft_BuiL600
		$a_01_3 = {72 65 63 6f 76 77 73 5f 4d 65 64 6f 6e 66 69 67 } //2 recovws_Medonfig
		$a_01_4 = {69 6d 6b 6e 5f 46 6f 72 64 69 73 63 } //2 imkn_Fordisc
		$a_01_5 = {57 69 6e 43 64 73 5f 47 65 74 44 69 73 76 31 5f 30 } //2 WinCds_GetDisv1_0
		$a_01_6 = {77 6d 69 6d 5f 64 72 61 77 69 6e 4d 64 52 65 73 } //2 wmim_drawinMdRes
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2) >=14
 
}