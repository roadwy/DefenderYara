
rule Ransom_Win32_StopCrypt_PBY_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 8b 55 90 01 01 83 0d 90 02 08 81 45 90 01 01 47 86 c8 61 8b c2 c1 e8 05 03 45 90 01 01 c7 05 90 02 0a 33 45 90 01 01 33 c1 2b f0 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}