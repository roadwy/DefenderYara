
rule Ransom_Win32_Conti_MBK_MTB{
	meta:
		description = "Ransom:Win32/Conti.MBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 0f 44 c8 88 0e 33 c9 41 81 f9 [0-04] 72 90 0a 30 00 69 c1 [0-04] 33 d2 2d [0-04] 0f af c1 f7 f3 85 d2 0f b6 ca 8d 42 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}