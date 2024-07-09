
rule Ransom_Win32_BlackSuit_YY_MTB{
	meta:
		description = "Ransom:Win32/BlackSuit.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 98 8b 45 ec 8b 55 d4 01 02 8b 45 c4 03 45 90 (03 45 98 89 45 a4 [0-10] 8b 5d a4 2b d8 [0-10] 2b d8 [0-10] 2b d8 8b 45 d4 31 18 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 |)} //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}