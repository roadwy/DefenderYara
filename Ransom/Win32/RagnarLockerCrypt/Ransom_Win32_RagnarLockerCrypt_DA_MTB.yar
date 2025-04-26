
rule Ransom_Win32_RagnarLockerCrypt_DA_MTB{
	meta:
		description = "Ransom:Win32/RagnarLockerCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 a4 83 c2 01 89 55 a4 81 7d a4 ?? ?? 00 00 0f 83 ?? ?? ?? ?? 8b 45 a4 8b 4d b4 8b 14 81 89 95 ?? ?? ?? ?? a1 ?? ?? ?? ?? 89 85 ?? ?? ?? ?? 8b 8d 90 1b 02 2b 4d a4 89 8d 90 1b 02 8b 55 c4 c1 e2 ?? 89 55 c4 8b 85 90 1b 02 33 85 90 1b 04 89 85 90 1b 02 8b 4d c4 81 c1 ?? ?? ?? ?? 89 4d c4 c1 85 90 1b 02 ?? 8b 45 c4 99 81 e2 ?? ?? ?? 00 03 c2 c1 f8 ?? 89 45 c4 8b 95 90 1b 02 33 95 90 1b 04 89 95 90 1b 02 8b 45 a4 8b 4d ec 8b 95 90 1b 02 89 14 81 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}