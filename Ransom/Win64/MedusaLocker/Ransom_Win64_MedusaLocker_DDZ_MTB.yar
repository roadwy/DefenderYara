
rule Ransom_Win64_MedusaLocker_DDZ_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.DDZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 48 8b c3 49 f7 f7 48 8b 06 0f b6 0c 0a 41 32 0c 18 88 0c 03 48 ff c3 48 3b dd 72 d2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}