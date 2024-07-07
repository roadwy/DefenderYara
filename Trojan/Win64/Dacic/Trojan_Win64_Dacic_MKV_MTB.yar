
rule Trojan_Win64_Dacic_MKV_MTB{
	meta:
		description = "Trojan:Win64/Dacic.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ef 03 d7 c1 fa 05 8b c2 c1 e8 1f 03 d0 0f be c2 6b c8 38 40 0f b6 c7 2a c1 04 36 41 30 00 ff c7 4d 8d 40 90 01 01 83 ff 27 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}