
rule Ransom_Win32_StopCrypt_SE_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e1 04 03 4d ?? c1 e8 ?? 03 45 ?? 33 ce 33 c1 89 4d ?? 89 45 ?? 8b 45 ?? 01 05 } //1
		$a_03_1 = {8b 45 0c 83 6d ?? ?? ?? 01 45 ?? 83 6d ?? ?? 8b 45 ?? 8b 4d ?? 31 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}