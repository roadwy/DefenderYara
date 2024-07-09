
rule Ransom_Win32_StopCrypt_MMK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 45 f4 89 45 e8 8b 45 f4 29 45 f0 25 [0-04] 8b 55 f0 8b c2 8d 4d e8 e8 [0-04] 8b 4d f8 03 ca c1 ea [0-01] 89 55 f4 8b 45 dc 01 45 f4 8b 45 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}