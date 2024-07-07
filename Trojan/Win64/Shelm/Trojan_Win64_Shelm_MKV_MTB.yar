
rule Trojan_Win64_Shelm_MKV_MTB{
	meta:
		description = "Trojan:Win64/Shelm.MKV!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 d8 31 d2 48 f7 f6 41 8a 04 1f 48 8b 8d a8 0f 00 00 32 04 11 4c 89 f1 89 c2 e8 ef 72 ff ff 48 89 fb eb c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}