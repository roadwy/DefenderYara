
rule Backdoor_Linux_Gafgyt_CA_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {e1 a0 c0 0d e9 2d 00 0e e9 2d d8 00 e2 4c b0 10 e2 4d d0 14 e5 0b 00 20 e3 a0 0b 02 eb 90 02 05 e1 a0 30 00 e5 0b 30 18 e5 1b 30 18 e1 a0 00 03 e3 a0 10 00 e3 a0 2b 02 eb 90 02 05 e5 1b 30 18 e5 0b 30 14 e2 8b 30 08 e5 0b 30 1c e5 9b 20 04 e5 1b c0 1c e2 4b 30 18 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}