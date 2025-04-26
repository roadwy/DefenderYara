
rule Trojan_Win64_Zusy_HNAE_MTB{
	meta:
		description = "Trojan:Win64/Zusy.HNAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {9b 92 e4 c1 fe e1 e6 e7 e4 e5 1a 37 4e 5c 65 66 6b 69 64 52 64 68 65 65 4d 67 70 78 2a 17 0e 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}