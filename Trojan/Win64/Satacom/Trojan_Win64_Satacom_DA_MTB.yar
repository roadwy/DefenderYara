
rule Trojan_Win64_Satacom_DA_MTB{
	meta:
		description = "Trojan:Win64/Satacom.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e9 ?? 33 c8 69 c9 ?? ?? ?? ?? 03 ca 89 4c 95 ?? 8b c1 49 03 d0 49 3b d1 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}