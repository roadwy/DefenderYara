
rule Trojan_Win64_LovGate_CCJX_MTB{
	meta:
		description = "Trojan:Win64/LovGate.CCJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 4c 70 fe 89 ca c1 ea 08 31 ca 88 54 37 ff 48 83 fe 43 74 ?? 0f b7 0c 70 89 ca c1 ea 08 31 ca 88 14 37 48 83 c6 02 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}