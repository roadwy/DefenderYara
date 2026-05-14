
rule Trojan_Win64_SantaStealer_NH_MTB{
	meta:
		description = "Trojan:Win64/SantaStealer.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 0c c1 e0 0d 31 d0 89 44 24 0c 8b 44 24 0c 8b 54 24 0c c1 e8 11 31 d0 89 44 24 0c 8b 44 24 0c 8b 54 24 0c c1 e0 05 31 d0 89 44 24 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}