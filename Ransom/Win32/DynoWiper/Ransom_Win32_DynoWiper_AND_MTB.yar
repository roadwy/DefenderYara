
rule Ransom_Win32_DynoWiper_AND_MTB{
	meta:
		description = "Ransom:Win32/DynoWiper.AND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ce d3 e0 85 c2 0f 84 9e 00 00 00 66 0f be c3 c7 45 c8 07 00 00 00 c7 45 c4 01 00 00 00 66 89 45 b4 33 c0 66 89 45 b6 68 ?? 49 42 00 8d 55 b4 c7 45 fc 01 00 00 00 8d 4d d4 e8 ?? ?? ?? ?? 83 c4 04 c6 45 fc 03 83 7d c8 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}