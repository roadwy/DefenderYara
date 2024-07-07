
rule Trojan_Win32_Gepys_RPO_MTB{
	meta:
		description = "Trojan:Win32/Gepys.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 38 88 dc 89 f1 fe c4 88 c8 f6 e4 88 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}