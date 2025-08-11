
rule Trojan_Win32_ClickFix_YAP_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.YAP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,2d 01 2d 01 04 00 00 "
		
	strings :
		$a_00_0 = {50 00 6f 00 77 00 65 00 72 00 53 00 68 00 65 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 } //100 PowerShell.exe
		$a_00_1 = {48 00 69 00 64 00 64 00 65 00 6e 00 20 00 } //100 Hidden 
		$a_00_2 = {68 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 } //100 htps://
		$a_00_3 = {49 00 6e 00 73 00 65 00 72 00 74 00 28 00 32 00 2c 00 27 00 74 00 27 00 29 00 } //1 Insert(2,'t')
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100+(#a_00_3  & 1)*1) >=301
 
}