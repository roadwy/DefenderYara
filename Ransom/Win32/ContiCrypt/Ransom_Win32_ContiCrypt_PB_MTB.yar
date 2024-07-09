
rule Ransom_Win32_ContiCrypt_PB_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f7 53 0f b6 06 46 85 c0 74 ?? 51 ?? c7 04 e4 ?? ?? ?? ?? 59 bb ?? ?? ?? ?? 8b d6 c7 45 fc ?? ?? ?? ?? d3 c0 8a fc 8a e6 d3 cb ff 4d ?? 75 [0-04] 8b c3 [0-04] aa 49 75 } //1
		$a_03_1 = {8b cf 23 4d ?? 75 ?? 46 8b 45 ?? 0f b6 1c 30 8b 55 ?? d3 c2 23 d3 ac 0a c2 88 07 47 ff 4d ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}