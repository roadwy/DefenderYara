
rule Trojan_BAT_Azorult_PAF_MTB{
	meta:
		description = "Trojan:BAT/Azorult.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 31 5c 3a 34 31 5c 3a 34 31 5c 3a 34 31 5c 3a 34 31 5c 3a 34 31 5c 3a 34 31 5c } //01 00  41\:41\:41\:41\:41\:41\:41\
		$a_01_1 = {53 65 63 75 72 69 74 79 43 6f 6e 74 65 78 74 52 75 6e 44 61 74 61 2e 4d 79 } //01 00  SecurityContextRunData.My
		$a_01_2 = {67 65 74 5f 52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //01 00  get_ResourceManager
		$a_01_3 = {67 65 74 5f 74 78 74 50 61 73 73 77 6f 72 64 31 } //01 00  get_txtPassword1
		$a_01_4 = {62 74 6e 5f 4c 6f 67 69 6e 31 5f 43 6c 69 63 6b } //01 00  btn_Login1_Click
		$a_01_5 = {67 65 74 5f 74 78 74 55 73 65 72 6e 61 6d 65 31 } //01 00  get_txtUsername1
		$a_01_6 = {67 65 74 5f 57 65 62 53 65 72 76 69 63 65 73 } //01 00  get_WebServices
		$a_01_7 = {67 65 74 5f 62 74 6e 5f 4c 6f 67 69 6e 31 } //01 00  get_btn_Login1
		$a_01_8 = {67 65 74 5f 4c 6f 67 69 6e 53 50 4f 43 } //01 00  get_LoginSPOC
		$a_01_9 = {5f 63 68 6b 53 68 6f 77 70 61 73 73 } //01 00  _chkShowpass
		$a_01_10 = {6d 5f 4c 6f 67 69 6e 53 50 4f 43 } //01 00  m_LoginSPOC
		$a_01_11 = {4d 79 43 6f 6d 70 75 74 65 72 } //00 00  MyComputer
	condition:
		any of ($a_*)
 
}