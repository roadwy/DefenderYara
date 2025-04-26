
rule Ransom_Win32_StopCrypt_SLS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b ca c1 e9 ?? 03 4d ?? 8b da c1 e3 ?? 03 5d ?? 8d 04 16 33 cb 33 c8 89 45 ?? 89 4d ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 8b 45 ?? 29 45 ?? 8b 45 ?? c1 e0 ?? 03 45 ?? 89 45 ?? 8b 45 ?? 03 45 } //1
		$a_03_1 = {8b 45 0c 01 45 ?? 83 6d fc ?? 8b 45 ?? 8b 4d ?? 31 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}