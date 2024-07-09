
rule Backdoor_Linux_ConnectBack_B_MTB{
	meta:
		description = "Backdoor:Linux/ConnectBack.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 db f7 e3 53 43 53 6a 02 b0 66 89 e1 cd 80 97 5b 68 ?? ?? ?? ?? 68 02 00 ?? ?? 89 e1 6a 66 58 50 51 57 89 e1 43 cd 80 85 c0 79 19 4e 74 3d 68 a2 00 00 00 58 6a 00 6a 05 89 e3 31 c9 cd 80 85 c0 79 bd eb 27 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}