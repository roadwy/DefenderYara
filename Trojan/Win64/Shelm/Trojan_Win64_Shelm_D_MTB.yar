
rule Trojan_Win64_Shelm_D_MTB{
	meta:
		description = "Trojan:Win64/Shelm.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 44 24 48 48 8d 44 24 50 48 8b 4c 24 40 45 33 c9 ba 10 66 00 00 48 89 44 24 20 ff 15 ?? ?? 00 00 85 c0 74 ?? 48 8b 4c 24 50 48 8d 44 24 30 48 89 44 24 28 45 33 c9 48 8d 85 70 03 00 00 45 33 c0 33 d2 48 89 44 24 20 ff 15 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}