
rule Trojan_Win64_Nanocore_GPD_MTB{
	meta:
		description = "Trojan:Win64/Nanocore.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b d1 80 32 90 01 01 41 ff c0 48 8d 52 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}