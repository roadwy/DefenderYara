
rule Ransom_Win32_RyukCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/RyukCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f4 83 c1 01 89 4d 90 01 01 8b 55 90 01 01 3b 15 90 01 04 7d 90 01 01 8b 45 90 01 01 0f be 88 90 01 04 8b 45 90 01 01 99 f7 3d 90 01 04 0f be 92 90 01 04 33 ca 8b 45 90 01 01 88 88 90 01 04 eb 90 00 } //1
		$a_03_1 = {8b 45 f0 83 c0 01 89 45 f0 8b 4d f0 0f be 89 90 01 04 8b 45 90 01 01 99 f7 3d 90 01 04 0f be 92 90 01 04 33 ca 8b 45 90 01 01 88 88 90 01 04 8b 4d f0 83 c1 01 89 4d f0 8b 55 90 01 01 89 55 90 01 01 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}