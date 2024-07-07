
rule Backdoor_Linux_Tsunami_DQ_MTB{
	meta:
		description = "Backdoor:Linux/Tsunami.DQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 08 8a 00 25 ff 00 00 00 83 ec 0c 50 e8 90 01 04 83 c4 10 89 c3 8b 45 0c 8a 00 25 ff 00 00 00 83 ec 0c 50 e8 90 01 04 83 c4 10 39 c3 75 90 01 01 8b 45 0c 40 8b 55 08 42 83 ec 08 50 52 e8 0d fd ff ff 83 c4 10 85 c0 74 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}