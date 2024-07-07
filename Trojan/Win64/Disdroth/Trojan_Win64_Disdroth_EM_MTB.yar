
rule Trojan_Win64_Disdroth_EM_MTB{
	meta:
		description = "Trojan:Win64/Disdroth.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 40 00 00 00 41 8b c8 83 e1 3f 2b d1 8a ca 48 8b d0 48 d3 ca 49 33 d0 4b 87 94 fe 00 07 05 00 eb 89 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}