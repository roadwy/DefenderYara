
rule Trojan_Linux_SamDust_N_MTB{
	meta:
		description = "Trojan:Linux/SamDust.N!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 34 00 42 a9 76 31 df 12 9c 1c 64 ec e0 f1 40 07 fb 15 f2 30 32 c8 20 83 4a 63 7b c8 20 83 0c 95 ae c8 93 } //00 00 
	condition:
		any of ($a_*)
 
}