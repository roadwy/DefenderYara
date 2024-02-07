
rule Ransom_Win32_Makop_SS_MTB{
	meta:
		description = "Ransom:Win32/Makop.SS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {65 00 64 00 7a 00 6a 00 6b 00 70 00 68 00 76 00 65 00 73 00 77 00 2e 00 75 00 78 00 65 00 } //01 00  edzjkphvesw.uxe
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 53 00 75 00 72 00 6e 00 61 00 6d 00 65 00 73 00 } //01 00  InternalSurnames
		$a_01_2 = {54 00 6f 00 67 00 20 00 63 00 65 00 6a 00 75 00 6d 00 75 00 20 00 73 00 69 00 76 00 61 00 6a 00 75 00 64 00 61 00 6b 00 61 00 6d 00 6f 00 66 00 20 00 64 00 69 00 77 00 69 00 78 00 6f 00 } //01 00  Tog cejumu sivajudakamof diwixo
		$a_01_3 = {44 00 56 00 6f 00 6d 00 65 00 6b 00 69 00 6c 00 20 00 63 00 6f 00 66 00 61 00 74 00 61 00 6c 00 6f 00 78 00 6f 00 77 00 65 00 64 00 6f 00 73 00 20 00 6b 00 6f 00 66 00 6f 00 6d 00 75 00 6a 00 69 00 6c 00 6f 00 67 00 75 00 72 00 75 00 20 00 64 00 6f 00 6b 00 75 00 6e 00 75 00 76 00 20 00 7a 00 69 00 68 00 61 00 74 00 65 00 78 00 6f 00 70 00 65 00 20 00 68 00 6f 00 70 00 61 00 6c 00 69 00 74 00 65 00 62 00 6f 00 } //00 00  DVomekil cofataloxowedos kofomujiloguru dokunuv zihatexope hopalitebo
	condition:
		any of ($a_*)
 
}