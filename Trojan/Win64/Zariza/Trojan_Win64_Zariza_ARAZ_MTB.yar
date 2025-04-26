
rule Trojan_Win64_Zariza_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/Zariza.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 48 89 45 00 48 c7 45 08 04 00 00 00 44 88 0e 49 ff c1 4d 89 ec e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}