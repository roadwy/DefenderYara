
rule Trojan_Win32_ClickFix_DEN_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DEN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,6e 00 6e 00 02 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2f 00 67 00 65 00 2f 00 62 00 6f 00 72 00 65 00 6e 00 } //10 /ge/boren
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10) >=110
 
}