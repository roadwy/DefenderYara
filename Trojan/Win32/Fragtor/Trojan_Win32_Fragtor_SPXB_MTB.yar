
rule Trojan_Win32_Fragtor_SPXB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SPXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 61 69 75 67 61 69 75 65 67 41 75 69 61 73 67 75 69 65 68 67 } //02 00  CaiugaiuegAuiasguiehg
		$a_01_1 = {44 61 73 67 69 75 6f 61 65 75 68 67 68 67 61 68 69 65 67 68 67 } //02 00  Dasgiuoaeuhghgahieghg
		$a_01_2 = {52 61 66 67 61 66 61 68 75 66 67 68 61 75 68 67 68 67 68 } //00 00  Rafgafahufghauhghgh
	condition:
		any of ($a_*)
 
}