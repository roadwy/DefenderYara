
rule Trojan_Win64_Bumblebee_FFZ_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.FFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 89 ca 41 83 f2 ff 41 89 c3 45 21 d3 83 f0 ff 21 c1 41 09 cb 44 88 da 41 88 14 30 31 c0 8b 4c 24 ?? 83 e8 01 29 c1 89 4c 24 08 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}