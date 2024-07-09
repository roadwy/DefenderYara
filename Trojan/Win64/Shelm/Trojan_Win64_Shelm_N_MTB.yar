
rule Trojan_Win64_Shelm_N_MTB{
	meta:
		description = "Trojan:Win64/Shelm.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 0f b6 0c 12 41 88 08 46 88 0c 12 41 0f b6 10 49 03 d1 0f b6 ca 0f b6 14 ?? 30 13 48 ff c3 49 83 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}