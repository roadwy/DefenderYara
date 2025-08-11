
rule Trojan_Win32_ClickFix_DCP_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DCP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {2e 00 54 00 6f 00 43 00 48 00 61 00 52 00 61 00 72 00 52 00 61 00 79 00 28 00 29 00 } //10 .ToCHaRarRay()
		$a_00_2 = {5b 00 61 00 72 00 72 00 61 00 79 00 5d 00 3a 00 3a 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 28 00 24 00 } //10 [array]::Reverse($
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=120
 
}