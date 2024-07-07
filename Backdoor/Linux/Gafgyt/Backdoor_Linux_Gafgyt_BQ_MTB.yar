
rule Backdoor_Linux_Gafgyt_BQ_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.BQ!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {bd 27 2c 00 bf af 28 00 be af 21 f0 a0 03 10 00 bc af 30 00 c4 af 1c 00 c0 af 30 00 c4 8f 64 81 99 90 01 04 00 09 f8 20 03 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}