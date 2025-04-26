
rule Ransom_Win64_MedusaLocker_ZIN_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.ZIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 53 40 48 8b cb e8 ?? ?? ?? ?? 48 8b c5 48 89 ab 80 00 00 00 0f b6 44 18 40 30 07 48 ff c7 48 ff 83 80 00 00 00 48 83 ee 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}