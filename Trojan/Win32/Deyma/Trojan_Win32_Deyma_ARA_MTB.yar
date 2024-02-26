
rule Trojan_Win32_Deyma_ARA_MTB{
	meta:
		description = "Trojan:Win32/Deyma.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {80 34 30 41 40 3b c1 72 f7 } //00 00 
	condition:
		any of ($a_*)
 
}