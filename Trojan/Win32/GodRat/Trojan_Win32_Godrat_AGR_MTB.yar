
rule Trojan_Win32_Godrat_AGR_MTB{
	meta:
		description = "Trojan:Win32/Godrat.AGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 3d 10 f0 40 00 68 ?? 3d 41 00 56 ff d7 68 ?? 3d 41 00 56 89 44 24 20 ff d7 68 ?? 3d 41 00 56 89 44 24 3c ff d7 68 ?? 3d 41 00 56 89 44 24 1c ff d7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}