
rule Trojan_Win32_Bulta_RPH_MTB{
	meta:
		description = "Trojan:Win32/Bulta.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 44 24 1c 8b 44 24 1c 89 44 24 18 8b 44 24 14 8b 4c 24 20 d3 e8 89 44 24 10 8b 44 24 3c 01 44 24 10 8b 4c 24 10 33 4c 24 18 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}