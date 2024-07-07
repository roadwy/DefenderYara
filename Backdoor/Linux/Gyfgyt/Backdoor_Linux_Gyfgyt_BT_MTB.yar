
rule Backdoor_Linux_Gyfgyt_BT_MTB{
	meta:
		description = "Backdoor:Linux/Gyfgyt.BT!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c0 b5 45 8c 08 00 c3 8f 0c 00 c2 8f 90 02 05 23 20 62 00 18 80 82 8f 80 18 05 00 30 c4 42 24 21 10 62 00 00 00 44 ac 18 80 82 8f 80 18 05 00 30 c4 42 24 21 10 62 00 00 00 42 8c 21 e8 c0 03 20 00 be 8f 28 00 bd 27 08 00 e0 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}