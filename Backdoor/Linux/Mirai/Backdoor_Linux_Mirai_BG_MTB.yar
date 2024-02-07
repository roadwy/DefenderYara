
rule Backdoor_Linux_Mirai_BG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.BG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 77 6e 61 6d 73 6d 71 66 68 64 } //01 00  zwnamsmqfhd
		$a_01_1 = {69 6b 6c 6d 68 6f 6a 64 } //01 00  iklmhojd
		$a_01_2 = {63 6d 6e 76 6d 72 4f 61 59 6d 6e 76 68 64 65 } //01 00  cmnvmrOaYmnvhde
		$a_00_3 = {63 68 6d 6f 64 20 2b 78 20 73 68 61 6b 65 72 } //01 00  chmod +x shaker
		$a_01_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //00 00  npxXoudifFeEgGaACScs
	condition:
		any of ($a_*)
 
}