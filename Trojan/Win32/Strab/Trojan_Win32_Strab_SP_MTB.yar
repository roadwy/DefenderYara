
rule Trojan_Win32_Strab_SP_MTB{
	meta:
		description = "Trojan:Win32/Strab.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 f8 83 c2 01 89 55 f8 83 7d f8 04 7d 1e 8b 45 f8 0f b6 4c 05 f4 51 8d 55 8c 52 8b 4d e0 e8 90 01 04 8b 4d f8 88 44 0d f4 eb d3 90 00 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}