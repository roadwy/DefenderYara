
rule Trojan_Win32_LokiBot_SCMB_MTB{
	meta:
		description = "Trojan:Win32/LokiBot.SCMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 45 f8 8b 45 f8 03 45 e4 c7 05 ?? ?? ?? ?? ee 3d ea f4 33 c2 33 c1 2b f8 83 3d ?? ?? ?? ?? 0c 89 45 f8 75 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}