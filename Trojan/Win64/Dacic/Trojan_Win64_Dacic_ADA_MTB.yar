
rule Trojan_Win64_Dacic_ADA_MTB{
	meta:
		description = "Trojan:Win64/Dacic.ADA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 03 c0 66 90 b8 9d 82 97 53 4d 8d 40 01 f7 e9 c1 fa 04 8b c2 c1 e8 1f 03 d0 0f be c2 6b d0 31 0f b6 c1 ff c1 2a c2 04 30 41 30 40 ff 83 f9 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}