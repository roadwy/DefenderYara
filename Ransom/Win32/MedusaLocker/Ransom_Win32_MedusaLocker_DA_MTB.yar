
rule Ransom_Win32_MedusaLocker_DA_MTB{
	meta:
		description = "Ransom:Win32/MedusaLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 8d 1c ff ff ff 83 c1 90 01 01 89 8d 90 01 04 8b 95 90 1b 01 3b 95 90 01 04 74 37 8b 85 90 1b 01 50 8d 8d 90 01 04 e8 50 1c 00 00 8d 8d 90 01 04 51 e8 34 b6 ff ff 83 c4 04 50 8d 4d fb e8 18 86 01 00 8d 8d 90 01 04 e8 8d 19 00 00 eb ac 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}