
rule Ransom_Win32_StopCrypt_PMA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 83 90 02 06 2b fe 8b cf c1 e1 04 03 4d e8 8b c7 c1 e8 05 03 45 f4 03 d7 33 ca 33 c8 68 90 02 04 8d 45 f8 50 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}