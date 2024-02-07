
rule Trojan_Win32_Zusy_CK_MTB{
	meta:
		description = "Trojan:Win32/Zusy.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 69 6e 65 6e 74 68 69 6d } //02 00  Continenthim
		$a_01_1 = {43 6f 76 65 72 6c 6f 74 } //02 00  Coverlot
		$a_01_2 = {4d 61 6a 6f 72 74 68 72 65 65 } //02 00  Majorthree
		$a_01_3 = {57 61 76 65 73 70 6f 74 } //00 00  Wavespot
	condition:
		any of ($a_*)
 
}