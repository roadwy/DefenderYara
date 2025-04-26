
rule Trojan_Win64_Rugmi_MV_MTB{
	meta:
		description = "Trojan:Win64/Rugmi.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca c1 e2 ?? 31 ca 41 89 d0 41 c1 e8 ?? 41 31 d0 44 89 c1 c1 e1 ?? 44 31 c1 89 4c 05 ?? 48 83 c0 ?? 48 83 f8 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}