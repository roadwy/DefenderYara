
rule Trojan_BAT_Tnega_HWJ_MTB{
	meta:
		description = "Trojan:BAT/Tnega.HWJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_81_0 = {58 52 61 69 6c 73 2e 43 6f 6e 74 72 6f 6c 73 } //01 00  XRails.Controls
		$a_81_1 = {53 6c 6f 77 6c 6f 72 69 73 } //01 00  Slowloris
		$a_81_2 = {53 6c 6f 77 6c 6f 72 69 73 54 68 72 65 61 64 } //01 00  SlowlorisThread
		$a_81_3 = {54 77 69 63 65 53 6c 69 63 65 50 61 6e 65 6c 2e 55 49 } //01 00  TwiceSlicePanel.UI
		$a_81_4 = {43 72 65 64 65 6e 74 69 61 6c 4d 61 6e 61 67 65 6d 65 6e 74 } //01 00  CredentialManagement
		$a_81_5 = {67 65 74 5f 55 73 65 53 79 73 74 65 6d 50 61 73 73 77 6f 72 64 43 68 61 72 } //01 00  get_UseSystemPasswordChar
		$a_81_6 = {44 6f 6d 61 69 6e 56 69 73 69 62 6c 65 50 61 73 73 77 6f 72 64 } //01 00  DomainVisiblePassword
		$a_81_7 = {73 65 74 5f 53 65 63 75 72 65 50 61 73 73 77 6f 72 64 } //00 00  set_SecurePassword
	condition:
		any of ($a_*)
 
}