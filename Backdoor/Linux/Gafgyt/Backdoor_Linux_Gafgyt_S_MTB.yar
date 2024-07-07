
rule Backdoor_Linux_Gafgyt_S_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.S!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 16 51 55 d2 08 41 2c 31 12 60 fc 7f 90 01 01 62 9c 91 9c 93 ec 33 1c 33 9a 97 50 d6 95 91 ec 31 18 51 12 22 33 64 73 65 03 67 4d d1 0b 41 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}