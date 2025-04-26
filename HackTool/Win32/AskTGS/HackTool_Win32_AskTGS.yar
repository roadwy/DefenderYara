
rule HackTool_Win32_AskTGS{
	meta:
		description = "HackTool:Win32/AskTGS,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0a 00 00 "
		
	strings :
		$a_80_0 = {61 73 6b 74 67 73 20 6b 65 72 62 65 72 6f 73 20 63 6c 69 65 6e 74 } //asktgs kerberos client  3
		$a_80_1 = {2a 20 74 69 63 6b 65 74 20 69 6e 20 66 69 6c 65 20 27 25 73 27 } //* ticket in file '%s'  1
		$a_80_2 = {6b 75 6c 6c 5f 6d 5f 6b 65 72 62 65 72 6f 73 5f 68 65 6c 70 65 72 5f 75 74 69 6c 5f 73 61 76 65 72 65 70 61 73 6b 72 62 63 72 65 64 } //kull_m_kerberos_helper_util_saverepaskrbcred  1
		$a_80_3 = {6b 75 6c 6c 5f 6d 5f 6b 65 72 62 65 72 6f 73 5f 61 73 6e 31 5f 68 65 6c 70 65 72 5f 62 75 69 6c 64 5f 6b 72 62 63 72 65 64 } //kull_m_kerberos_asn1_helper_build_krbcred  1
		$a_80_4 = {6b 75 6c 6c 5f 6d 5f 6b 65 72 62 65 72 6f 73 5f 68 65 6c 70 65 72 5f 75 74 69 6c 5f 70 74 74 5f 64 61 74 61 } //kull_m_kerberos_helper_util_ptt_data  1
		$a_80_5 = {74 67 74 2e 6b 69 72 62 69 } //tgt.kirbi  1
		$a_80_6 = {4c 73 61 43 61 6c 6c 41 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 50 61 63 6b 61 67 65 } //LsaCallAuthenticationPackage  1
		$a_80_7 = {6b 72 62 63 72 65 64 69 6e 66 6f } //krbcredinfo  1
		$a_80_8 = {74 69 63 6b 65 74 2d 69 6e 66 6f } //ticket-info  1
		$a_80_9 = {67 65 6e 74 69 6c 6b 69 77 69 } //gentilkiwi  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=6
 
}