
rule Trojan_Win64_Vidar_ABVD_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ABVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 da 30 ca f6 d0 08 d0 } //2
		$a_03_1 = {89 da 80 e2 ?? ?? ?? 08 d0 08 cb f6 d1 34 ?? 08 c8 89 c1 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*3) >=5
 
}