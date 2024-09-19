
rule Backdoor_Linux_SAgnt_L_MTB{
	meta:
		description = "Backdoor:Linux/SAgnt.L!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {83 90 12 00 28 00 b3 af 20 00 b1 af 1c 00 b0 af 2c 00 bf af 10 00 bc af 21 88 40 00 ff ff 52 26 21 98 60 00 42 00 10 3c } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}