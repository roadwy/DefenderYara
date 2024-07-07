
rule Trojan_Win32_SmokeLoader_PMV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 00 36 4a 70 90 01 01 c7 86 01 ff 82 03 7d db 4b 63 88 27 bb 5a 21 68 70 d3 09 6b 89 fe 8c 26 ba 5a 20 68 70 61 9e 2d f7 ea e5 48 e2 90 01 01 98 8a 8a 01 8e ae 09 4e 8e 61 8f 7e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}