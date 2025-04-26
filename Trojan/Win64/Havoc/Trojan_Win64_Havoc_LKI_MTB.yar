
rule Trojan_Win64_Havoc_LKI_MTB{
	meta:
		description = "Trojan:Win64/Havoc.LKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 10 8b 45 f8 4c 63 c0 48 8b 45 10 4c 01 c0 31 ca 88 10 83 45 fc 01 83 45 f8 01 eb a4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}