
rule Ransom_Win32_SageCrypt_PAA_MTB{
	meta:
		description = "Ransom:Win32/SageCrypt.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 3d 04 f5 14 11 00 75 1b 8b 4d d0 3b cf 7d 14 8b 45 d4 0f af c6 99 f7 7d d8 6b c9 e3 2b c8 03 f1 89 75 dc 47 89 7d c0 8b 4d d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}