
rule Trojan_Win64_MeduzaStealer_MRY_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.MRY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 48 89 55 50 0f b6 44 15 ?? 30 03 48 8b 55 50 48 ff c2 48 89 55 ?? 48 8b c2 48 ff c3 48 83 ef 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}