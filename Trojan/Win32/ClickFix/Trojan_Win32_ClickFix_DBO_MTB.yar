
rule Trojan_Win32_ClickFix_DBO_MTB{
	meta:
		description = "Trojan:Win32/ClickFix.DBO!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,78 00 78 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //100 powershell
		$a_00_1 = {5b 00 53 00 63 00 52 00 69 00 50 00 74 00 42 00 6c 00 4f 00 63 00 4b 00 5d 00 3a 00 3a 00 43 00 72 00 45 00 61 00 54 00 65 00 28 00 } //10 [ScRiPtBlOcK]::CrEaTe(
		$a_00_2 = {5b 00 61 00 72 00 72 00 61 00 79 00 5d 00 3a 00 3a 00 52 00 65 00 76 00 65 00 72 00 73 00 65 00 28 00 24 00 } //10 [array]::Reverse($
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10) >=120
 
}