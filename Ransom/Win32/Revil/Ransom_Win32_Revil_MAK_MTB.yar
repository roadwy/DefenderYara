
rule Ransom_Win32_Revil_MAK_MTB{
	meta:
		description = "Ransom:Win32/Revil.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 06 f6 2d [0-04] 8a d0 2a d1 2a 15 [0-04] 3b 0d [0-04] a2 90 1b 00 88 15 90 1b 01 74 18 02 c0 2a c2 02 c1 04 [0-01] 83 c6 [0-01] 81 fe [0-04] a2 90 1b 00 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}