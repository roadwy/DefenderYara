
rule Ransom_Win32_Roger_STT_MTB{
	meta:
		description = "Ransom:Win32/Roger.STT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e0 8b f7 c1 ee 05 03 74 24 38 03 44 24 28 89 74 24 10 8b c8 e8 35 fe ff ff 33 c6 2b e8 81 3d ?? ?? ?? ?? d5 01 00 00 89 44 24 24 c7 05 ?? ?? ?? ?? 00 00 00 00 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}