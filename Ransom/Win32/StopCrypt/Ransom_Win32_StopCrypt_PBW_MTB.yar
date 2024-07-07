
rule Ransom_Win32_StopCrypt_PBW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 31 4d 90 01 01 8b 45 90 01 01 01 05 90 01 04 2b 75 90 01 01 83 0d 90 02 08 8b c6 c1 e8 05 03 45 90 01 01 8b ce c1 e1 04 03 4d 90 01 01 50 89 45 90 01 01 8d 14 33 8d 45 90 01 01 33 ca 50 c7 05 90 02 0a 89 4d 90 01 01 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}