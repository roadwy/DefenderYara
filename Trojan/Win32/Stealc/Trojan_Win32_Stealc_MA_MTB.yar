
rule Trojan_Win32_Stealc_MA_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 35 e0 f1 47 00 8b 7d f4 8b 4d f8 8d 04 3b d3 ef 89 45 ec c7 05 [0-09] 03 7d d4 8b 45 ec 31 45 fc 33 7d fc 81 3d ?? ?? ?? ?? 13 02 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}