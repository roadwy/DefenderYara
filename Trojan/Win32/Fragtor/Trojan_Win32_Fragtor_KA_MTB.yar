
rule Trojan_Win32_Fragtor_KA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.KA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 31 29 d3 01 df 81 e6 ?? ?? ?? ?? f7 d3 01 da 31 30 01 da 81 eb ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 40 43 21 d3 81 c1 ?? ?? ?? ?? 01 df 09 d7 81 f8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}