
rule Ransom_Win32_StopCrypt_RP_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 00 00 cc cc cc cc cc 56 8b f1 c7 06 90 01 01 c1 40 00 e8 90 01 01 01 00 00 f6 44 24 08 01 74 09 56 e8 90 01 01 03 00 00 83 c4 04 8b c6 5e c2 04 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}