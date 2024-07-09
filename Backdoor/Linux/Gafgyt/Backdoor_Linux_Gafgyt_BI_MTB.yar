
rule Backdoor_Linux_Gafgyt_BI_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BI!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 8a 00 25 ff 00 00 00 83 ec 08 50 ff 75 08 e8 [0-05] 83 c4 10 ff 45 f0 ff 45 0c 8b 45 0c 8a 00 84 c0 } //1
		$a_03_1 = {83 ec 08 ff 75 f4 ff 75 08 e8 [0-05] 83 c4 10 ff 45 f0 ff 4d 10 83 7d 10 00 7f [0-03] 8b 45 f0 c9 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}