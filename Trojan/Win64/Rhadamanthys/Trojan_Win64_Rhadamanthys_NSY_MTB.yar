
rule Trojan_Win64_Rhadamanthys_NSY_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.NSY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 0f 43 c2 45 89 c0 45 0f b6 04 08 44 30 44 04 ?? 48 8d 04 ?? 48 ff c0 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}