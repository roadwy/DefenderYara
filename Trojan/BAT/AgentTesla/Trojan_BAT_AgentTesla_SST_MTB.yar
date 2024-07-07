
rule Trojan_BAT_AgentTesla_SST_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 12 00 00 "
		
	strings :
		$a_01_0 = {4c 00 65 00 72 00 6c 00 69 00 62 00 72 00 6f 00 5f 00 49 00 4e 00 43 00 2e 00 42 00 61 00 69 00 64 00 75 00 } //1 Lerlibro_INC.Baidu
		$a_01_1 = {55 00 72 00 6c 00 49 00 64 00 65 00 6e 00 74 00 69 00 74 00 79 00 50 00 65 00 72 00 6d 00 69 00 73 00 73 00 69 00 6f 00 6e 00 } //1 UrlIdentityPermission
		$a_01_2 = {4c 00 65 00 72 00 6c 00 69 00 62 00 72 00 6f 00 5f 00 49 00 4e 00 43 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Lerlibro_INC.Resources
		$a_01_3 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 53 65 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.Se1.resources
		$a_01_4 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 66 6e 74 31 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.fnt1.resources
		$a_01_5 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 66 72 6d 48 52 50 61 6e 65 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.frmHRPanel.resources
		$a_01_6 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 66 72 6d 4d 49 53 50 61 6e 65 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.frmMISPanel.resources
		$a_01_7 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 66 72 6d 41 63 63 6f 75 6e 74 69 6e 67 50 61 6e 65 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.frmAccountingPanel.resources
		$a_01_8 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 66 72 6d 53 61 6c 65 73 50 61 6e 65 6c 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.frmSalesPanel.resources
		$a_01_9 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 66 72 6d 4d 61 69 6e 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.frmMain.resources
		$a_01_10 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.Resources.resources
		$a_01_11 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 75 63 55 73 65 72 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.ucUsers.resources
		$a_01_12 = {4c 65 72 6c 69 62 72 6f 5f 49 4e 43 2e 42 61 69 64 75 2e 72 65 73 6f 75 72 63 65 73 } //1 Lerlibro_INC.Baidu.resources
		$a_01_13 = {43 72 65 61 74 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Create__Instance__
		$a_01_14 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f } //1 Dispose__Instance__
		$a_01_15 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_16 = {64 65 66 61 75 6c 74 49 6e 73 74 61 6e 63 65 } //1 defaultInstance
		$a_01_17 = {73 65 74 5f 53 68 6f 77 49 6e 54 61 73 6b 62 61 72 } //1 set_ShowInTaskbar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1) >=18
 
}