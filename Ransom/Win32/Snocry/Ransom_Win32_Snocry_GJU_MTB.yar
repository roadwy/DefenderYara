
rule Ransom_Win32_Snocry_GJU_MTB{
	meta:
		description = "Ransom:Win32/Snocry.GJU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 10 56 68 f4 6d 41 00 c6 05 90 01 04 57 c6 05 90 01 04 72 c6 05 90 01 04 69 c6 05 90 01 04 74 c6 05 90 01 04 65 c6 05 90 01 04 50 c6 05 90 01 04 72 c6 05 90 01 04 6f c6 05 90 01 04 63 c6 05 90 01 04 65 c6 05 90 01 04 73 c6 05 90 01 04 73 c6 05 90 01 04 4d c6 05 90 01 04 65 c6 05 90 01 04 6d c6 05 90 01 04 6f c6 05 90 01 04 72 c6 05 90 01 04 79 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}