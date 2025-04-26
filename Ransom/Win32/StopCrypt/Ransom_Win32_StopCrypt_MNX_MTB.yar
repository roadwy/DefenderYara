
rule Ransom_Win32_StopCrypt_MNX_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.MNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c7 d3 ef 89 45 ec c7 05 ?? ?? ?? ?? ee 3d ea f4 03 7d d4 8b 45 ec 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75 } //1
		$a_03_1 = {8b fb d3 ef 8b 4d e0 03 c1 33 c2 03 7d dc 81 3d ?? ?? ?? ?? 21 01 00 00 89 45 fc } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}