
rule Ransom_Win64_MedusaLocker_MZT_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.MZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 48 c7 83 80 ?? ?? ?? ?? ?? ?? ?? 0f b6 44 18 40 30 07 48 ff c7 48 ff 83 80 00 00 00 48 83 ee 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}