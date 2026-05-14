
rule Backdoor_Linux_BrickStorm_A_MTB{
	meta:
		description = "Backdoor:Linux/BrickStorm.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 6f 66 63 66 6a 70 6f 69 6d 6d 6a 65 66 6e 68 6a 6a 65 68 6e 2e 66 75 6e 63 31 34 } //1 main.ofcfjpoimmjefnhjjehn.func14
		$a_01_1 = {6d 61 69 6e 2e 6f 63 66 65 70 6f 62 68 68 63 66 66 6e 65 62 64 70 65 61 66 2e 66 75 6e 63 31 } //1 main.ocfepobhhcffnebdpeaf.func1
		$a_01_2 = {6d 61 69 6e 2e 66 6e 66 66 65 6c 65 69 63 66 67 64 63 6e 6f 6d 6a 64 64 70 } //1 main.fnffeleicfgdcnomjddp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}