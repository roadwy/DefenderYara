
rule Backdoor_Linux_Gyfgyt_BV_MTB{
	meta:
		description = "Backdoor:Linux/Gyfgyt.BV!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {64 00 19 00 00 38 12 00 00 30 10 00 a6 28 21 00 a0 30 21 8f 82 80 18 90 02 05 8c 42 1b 5c 90 02 05 00 40 28 21 00 00 20 21 00 e5 18 21 00 67 40 2b 00 c4 10 21 01 02 20 21 00 80 10 21 af c3 00 1c af c2 00 18 8f c4 00 18 90 02 05 00 04 18 02 00 00 10 21 8f 82 80 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}