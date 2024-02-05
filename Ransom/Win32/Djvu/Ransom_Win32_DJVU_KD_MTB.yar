
rule Ransom_Win32_DJVU_KD_MTB{
	meta:
		description = "Ransom:Win32/DJVU.KD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e8 05 03 44 24 20 03 d5 33 c2 03 cf 33 c1 2b f0 } //01 00 
		$a_01_1 = {33 cb 31 4c 24 10 8b 44 24 10 29 44 24 14 } //00 00 
	condition:
		any of ($a_*)
 
}