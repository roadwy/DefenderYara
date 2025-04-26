
rule Trojan_Win64_DriverLoader_RDA_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 ee d1 fa 8b c2 c1 e8 1f 03 d0 41 8b c6 2a c2 0f be c0 6b c8 37 40 02 ce 41 30 08 ff c6 4d 8d 40 01 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}