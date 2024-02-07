
rule TrojanDownloader_Win32_CmdSecurityWid_B_dha{
	meta:
		description = "TrojanDownloader:Win32/CmdSecurityWid.B!dha,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 00 63 00 61 00 63 00 6c 00 73 00 } //01 00  icacls
		$a_02_1 = {5c 00 5c 00 3f 00 5c 00 90 01 02 3a 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 5c 00 63 00 6f 00 6d 00 5c 00 90 00 } //01 00 
		$a_00_2 = {2f 00 69 00 6e 00 68 00 65 00 72 00 69 00 74 00 61 00 6e 00 63 00 65 00 3a 00 72 00 } //01 00  /inheritance:r
		$a_00_3 = {2f 00 67 00 72 00 61 00 6e 00 74 00 3a 00 72 00 } //01 00  /grant:r
		$a_00_4 = {73 00 79 00 73 00 74 00 65 00 6d 00 3a 00 } //00 00  system:
	condition:
		any of ($a_*)
 
}