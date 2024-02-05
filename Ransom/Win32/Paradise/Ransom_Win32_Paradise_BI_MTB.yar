
rule Ransom_Win32_Paradise_BI_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 db 33 c9 33 d2 33 f6 33 ff ff d0 90 02 60 33 db 33 c9 33 d2 33 f6 33 ff ff d0 90 00 } //01 00 
		$a_01_1 = {0f 45 d0 8b 4d d8 8b 45 b0 88 14 01 83 3d 98 37 42 00 00 75 43 } //00 00 
	condition:
		any of ($a_*)
 
}