
rule Trojan_Win64_Small_EM_MTB{
	meta:
		description = "Trojan:Win64/Small.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 aa 48 8d 95 40 02 00 00 88 85 40 02 00 00 45 33 c9 0f b7 45 aa 44 8b c7 66 c1 e8 08 48 8b cb 88 85 41 02 00 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}