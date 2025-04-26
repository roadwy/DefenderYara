
rule Trojan_Win64_Khalesi_RK_MTB{
	meta:
		description = "Trojan:Win64/Khalesi.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 39 d0 74 14 49 89 c0 41 83 e0 1f 46 8a 04 ?? 44 30 04 01 48 ff c0 eb e7 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}