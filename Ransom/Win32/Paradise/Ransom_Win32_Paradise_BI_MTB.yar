
rule Ransom_Win32_Paradise_BI_MTB{
	meta:
		description = "Ransom:Win32/Paradise.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 db 33 c9 33 d2 33 f6 33 ff ff d0 [0-60] 33 db 33 c9 33 d2 33 f6 33 ff ff d0 } //1
		$a_01_1 = {0f 45 d0 8b 4d d8 8b 45 b0 88 14 01 83 3d 98 37 42 00 00 75 43 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}