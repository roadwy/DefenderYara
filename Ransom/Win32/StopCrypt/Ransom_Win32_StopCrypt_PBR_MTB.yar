
rule Ransom_Win32_StopCrypt_PBR_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 5d 90 01 01 c1 e3 04 03 5d 90 01 01 33 5d 90 01 01 81 3d 90 02 0a 75 90 01 01 33 c0 50 50 50 ff 15 90 01 04 8b 45 90 01 01 83 25 90 02 08 33 c3 2b f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}