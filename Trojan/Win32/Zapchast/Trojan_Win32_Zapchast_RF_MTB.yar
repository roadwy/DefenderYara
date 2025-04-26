
rule Trojan_Win32_Zapchast_RF_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 e4 f8 83 ec 24 8b 45 ?? 8b 4d ?? 83 f0 ?? 89 44 24 ?? 83 f1 00 89 4c 24 ?? c7 44 24 ?? 17 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}