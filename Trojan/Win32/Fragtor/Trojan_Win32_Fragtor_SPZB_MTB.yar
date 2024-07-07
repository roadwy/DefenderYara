
rule Trojan_Win32_Fragtor_SPZB_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SPZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {46 61 73 69 75 67 66 41 69 75 73 61 67 69 75 68 65 67 } //1 FasiugfAiusagiuheg
		$a_01_1 = {48 69 73 75 73 68 67 72 68 41 75 69 73 61 68 65 65 67 75 } //1 HisushgrhAuisaheegu
		$a_01_2 = {52 73 67 6f 69 73 61 67 75 69 73 61 68 67 } //1 Rsgoisaguisahg
		$a_01_3 = {56 6f 69 61 73 61 66 6f 61 65 67 38 68 73 61 75 76 } //1 Voiasafoaeg8hsauv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}