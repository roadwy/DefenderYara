
rule Trojan_Win64_MeduzaStealer_BSA_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 53 48 83 ec 60 48 8b 05 b3 6c 37 00 48 33 c4 48 89 44 24 50 33 c0 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_MeduzaStealer_BSA_MTB_2{
	meta:
		description = "Trojan:Win64/MeduzaStealer.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 50 48 8b 05 ?? ?? ?? ?? 48 33 c4 48 89 44 24 48 48 c7 44 24 30 00 00 00 00 48 c7 44 24 40 00 00 00 00 33 db 48 89 5c 24 40 33 ff 33 f6 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}