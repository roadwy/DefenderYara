
rule Trojan_Win64_Rhadamanthys_MKP_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.MKP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff d0 48 83 c4 20 43 8a 04 3c 4c 8b 7d 70 48 8b 4d ?? 41 02 04 0c 0f b6 c0 41 8a 04 04 48 8b 4d 80 4c 8b 65 e0 42 32 04 21 42 88 04 21 48 b8 51 63 bb ed 3e b6 72 96 48 03 05 2f 0c 13 00 48 83 ec 20 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}