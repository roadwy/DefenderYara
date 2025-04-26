
rule Ransom_Win32_ContiCryptor_MAK_MTB{
	meta:
		description = "Ransom:Win32/ContiCryptor.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {80 c2 20 46 c1 c1 [0-01] 03 f5 0f be c2 33 c8 43 8a 16 84 d2 75 d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}