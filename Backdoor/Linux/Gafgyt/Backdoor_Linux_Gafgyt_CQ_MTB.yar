
rule Backdoor_Linux_Gafgyt_CQ_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.CQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3c 1c 00 06 27 9c 33 48 03 99 e0 21 27 bd ef b0 af bf 10 4c af be 10 48 03 a0 f0 21 af bc 00 10 27 c2 00 2c af c2 00 28 8f 99 84 a8 [0-05] 03 20 f8 09 [0-05] 8f dc 00 10 af c2 00 18 8f c4 00 1c } //1
		$a_03_1 = {27 c2 00 44 00 40 20 21 8f c5 00 3c 8f c6 00 38 8f c7 00 28 8f 82 80 20 [0-05] 24 59 0e ac 03 20 f8 09 [0-05] 8f dc 00 10 14 40 00 28 [0-05] 27 c2 00 44 00 40 20 21 8f c5 00 3c 8f c6 00 34 8f c7 00 24 8f 82 80 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}