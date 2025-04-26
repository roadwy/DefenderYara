
rule Trojan_Win64_Cobaltstrike_FEA_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 45 33 f6 41 8b fe 48 8b 48 60 8a 41 02 4c 8b 61 18 49 83 c4 20 84 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}