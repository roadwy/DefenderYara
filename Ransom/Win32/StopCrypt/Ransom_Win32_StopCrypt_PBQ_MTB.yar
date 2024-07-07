
rule Ransom_Win32_StopCrypt_PBQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cf c1 e9 05 03 4d 90 01 01 03 c2 33 c8 8d 04 3b 33 c8 89 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 83 0d 90 02 06 2b f1 8b ce c1 e1 04 03 4d 90 01 01 8b c6 c1 e8 05 03 45 90 01 01 8d 14 33 33 ca 33 c8 2b f9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}