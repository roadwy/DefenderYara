
rule Ransom_Win32_StopCrypt_MYK_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 0c 8b 4d 08 c1 e0 04 89 01 5d c2 } //1
		$a_01_1 = {55 8b ec 8b 45 10 8b 4d 08 c1 e8 05 03 45 0c 89 01 5d c2 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Ransom_Win32_StopCrypt_MYK_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.MYK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 45 90 1b 00 83 3d ?? ?? ?? ?? ?? 75 } //1
		$a_03_1 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 8b 85 ?? ?? ?? ?? 01 45 90 1b 00 81 3d ?? ?? ?? ?? ?? ?? 00 00 75 } //1
		$a_03_2 = {8d 1c 01 8b 4d 6c d3 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 ?? 8b 85 80 fe ff ff 01 45 90 1b 01 8b 55 90 1b 01 33 d3 33 55 64 8d 8d } //1
		$a_03_3 = {8d 1c 10 d3 ea c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 55 ?? 8b 85 04 fe ff ff 01 45 90 1b 01 8b 4d 90 1b 01 33 cb 33 4d e8 8d 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=1
 
}