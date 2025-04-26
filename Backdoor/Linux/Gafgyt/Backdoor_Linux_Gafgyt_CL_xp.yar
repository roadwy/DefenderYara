
rule Backdoor_Linux_Gafgyt_CL_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.CL!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {bd 27 2c 00 bf af 28 00 be af 21 f0 a0 03 10 00 bc af 30 00 c4 af 1c 00 c0 af 30 00 c4 8f 68 81 99 8f 00 00 00 00 09 f8 20 03 00 } //1
		$a_00_1 = {21 28 40 00 20 80 82 8f 00 00 00 00 e0 07 59 24 09 f8 20 03 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}