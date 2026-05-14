
rule Trojan_Win64_Donut_PAA_MTB{
	meta:
		description = "Trojan:Win64/Donut.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 c1 81 e1 ff ff 0f 00 41 0f b6 0c 09 30 0c 02 48 83 c0 01 49 39 c0 75 e6 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}