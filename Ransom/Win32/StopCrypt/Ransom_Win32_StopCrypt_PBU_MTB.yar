
rule Ransom_Win32_StopCrypt_PBU_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e6 04 03 74 24 ?? 33 74 24 ?? 81 3d [0-0a] 75 [0-10] 33 74 24 ?? c7 05 [0-0a] 89 74 24 ?? 8b 44 24 ?? 29 44 24 ?? 81 44 24 ?? 47 86 c8 61 ff 4c 24 ?? 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}