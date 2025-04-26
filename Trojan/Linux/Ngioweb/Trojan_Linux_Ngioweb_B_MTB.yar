
rule Trojan_Linux_Ngioweb_B_MTB{
	meta:
		description = "Trojan:Linux/Ngioweb.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {60 01 0c b7 33 7a a5 cb 1e 84 c2 5b 21 f0 a9 93 60 01 0c b7 33 2d 7d 48 9f 4e a3 83 16 22 1d f8 6b bb 2d d5 f2 e4 3d 8b 65 2e 43 81 cf 8f bc 67 85 b7 ec 75 5f 7a a5 cb 1e 84 c2 5b 21 f0 a9 93 60 01 0c b7 33 7a a5 cb 1e 84 c2 5b 21 f0 a9 93 60 01 0c b7 33 a0 bf a9 bc d2 27 b5 35 62 76 35 ea 0c 5b 4e aa b5 53 3f 43 05 e6 35 59 28 d6 64 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}