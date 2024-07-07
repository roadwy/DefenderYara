
rule Ransom_Win32_StopCrypt_MZA_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 03 33 f9 8b 4d 90 02 01 d3 e8 c7 05 90 02 08 03 45 90 02 01 33 c7 83 3d 90 02 05 89 45 f0 90 00 } //1
		$a_03_1 = {25 bb 52 c0 5d 8b 4d 90 02 01 8b d1 c1 e2 90 02 01 03 55 90 02 01 8b c1 c1 e8 90 02 01 03 45 90 02 01 03 cb 33 d1 33 d0 89 55 90 02 01 89 35 90 02 04 8b 45 90 02 01 29 45 90 02 01 81 c3 90 02 04 ff 4d ec 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}