
rule TrojanDownloader_Win32_Phantu_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Phantu.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 03 00 "
		
	strings :
		$a_00_0 = {49 00 4e 00 20 00 50 00 4f 00 50 00 20 00 70 00 6f 00 70 00 55 00 52 00 4c 00 } //02 00  IN POP popURL
		$a_01_1 = {66 72 6d 50 6f 70 70 65 72 } //02 00  frmPopper
		$a_00_2 = {43 00 68 00 65 00 63 00 6b 00 55 00 52 00 4c 00 20 00 45 00 72 00 72 00 6f 00 72 00 3a 00 20 00 } //02 00  CheckURL Error: 
		$a_00_3 = {5c 00 70 00 6f 00 70 00 70 00 65 00 72 00 2e 00 76 00 62 00 70 00 } //00 00  \popper.vbp
	condition:
		any of ($a_*)
 
}