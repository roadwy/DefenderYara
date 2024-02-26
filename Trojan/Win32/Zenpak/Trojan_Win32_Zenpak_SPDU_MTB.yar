
rule Trojan_Win32_Zenpak_SPDU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {73 37 74 43 39 4c 79 2e 64 4c 6c } //02 00  s7tC9Ly.dLl
		$a_01_1 = {4c 6e 6c 74 65 65 68 4f 73 74 65 72 62 70 } //00 00  LnlteehOsterbp
	condition:
		any of ($a_*)
 
}