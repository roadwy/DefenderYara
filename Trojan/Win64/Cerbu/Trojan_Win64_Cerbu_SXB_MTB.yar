
rule Trojan_Win64_Cerbu_SXB_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 2c 01 00 00 ff 15 ?? ?? ?? ?? 48 8d 53 e8 83 c8 ff f0 0f c1 42 10 ff c8 85 c0 7f } //20
		$a_03_1 = {41 0f b7 00 49 83 c0 02 66 83 f8 61 72 ?? 41 ba e0 ff 00 00 66 41 03 c2 69 c9 01 01 00 00 0f b7 c0 03 c8 49 ff c9 75 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}