
rule Trojan_Win64_Rhadamanthys_ZKA_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.ZKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b cd 41 b8 ?? ?? ?? ?? 48 2b cb 49 8b d0 4c 8b db 42 8a 04 1e 41 32 03 42 88 04 19 49 83 c3 01 48 83 ea 01 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}