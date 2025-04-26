
rule Ransom_Win64_ARCrypt_AR_MTB{
	meta:
		description = "Ransom:Win64/ARCrypt.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 33 c9 45 33 c0 48 8d 95 d0 05 00 00 48 8b 0b ff 15 0f 81 06 00 48 8d 15 58 d0 07 00 48 8d 8d c0 03 00 00 ff 15 db 7f 06 00 48 8b 13 48 8d 8d c0 03 00 00 ff 15 cb 7f 06 00 48 8d 15 6c d0 07 00 48 8d 8d c0 03 00 00 ff 15 b7 7f 06 00 44 89 7c 24 28 4c 89 7c 24 20 4c 8d 8d c0 03 00 00 4c 8d 05 b7 b8 07 00 48 8d 15 c0 b8 07 00 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}