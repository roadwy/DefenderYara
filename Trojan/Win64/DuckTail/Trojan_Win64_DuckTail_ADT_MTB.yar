
rule Trojan_Win64_DuckTail_ADT_MTB{
	meta:
		description = "Trojan:Win64/DuckTail.ADT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 3b 00 75 22 83 0b ff eb 45 45 33 c9 48 8d 15 b6 c4 92 00 41 83 c8 ff 48 8d 0d a3 c4 92 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}