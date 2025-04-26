
rule Ransom_Win32_StopCrypt_MCK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 65 f0 00 2b df 25 [0-04] 81 6d f0 [0-04] 81 45 f0 [0-04] 8b 4d dc 8b c3 c1 e8 [0-01] 89 45 ec 8d 45 ec } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}