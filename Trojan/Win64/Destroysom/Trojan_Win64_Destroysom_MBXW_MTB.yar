
rule Trojan_Win64_Destroysom_MBXW_MTB{
	meta:
		description = "Trojan:Win64/Destroysom.MBXW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {59 65 6b 46 34 76 41 42 78 6d 39 78 46 53 77 6c 30 6b 61 35 64 65 45 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}