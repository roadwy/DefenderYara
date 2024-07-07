
rule Trojan_Win64_Cobaltstrike_LKBI_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.LKBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 85 c0 48 8b ce 48 0f 45 cb 48 8b d9 48 83 ef 01 75 90 02 10 ff 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}