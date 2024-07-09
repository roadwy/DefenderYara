
rule Trojan_Win64_Shelm_C_MTB{
	meta:
		description = "Trojan:Win64/Shelm.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 53 48 83 ec 30 0f 29 74 24 20 ff 15 ?? ?? ?? ?? 48 8b c8 33 d2 ff 15 ?? ?? ?? ?? 66 0f 6f 35 ?? ?? 00 00 33 c9 ba ?? ?? ?? ?? 41 b8 00 10 00 00 44 8d 49 40 ff 15 ?? ?? ?? ?? 48 8b d8 48 85 c0 75 ?? 48 8d 0d 26 12 00 00 ff 15 ?? ?? ?? ?? 8d 43 01 0f 28 74 24 20 48 83 c4 30 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}