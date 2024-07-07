
rule Backdoor_Linux_Mirai_DG_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DG!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {31 74 75 70 6e 71 30 74 75 71 6f 72 31 75 76 71 6f 72 32 76 77 72 70 73 32 76 77 72 70 73 32 76 77 72 70 73 } //1 1tupnq0tuqor1uvqor2vwrps2vwrps2vwrps
		$a_01_1 = {76 69 66 6d 6d 75 69 67 6e 6e 76 6a 67 6e 6e 77 6b 68 6f 6f 77 6b 68 6f 6f 77 6b 68 6f 6f } //1 vifmmuignnvjgnnwkhoowkhoowkhoo
		$a_01_2 = {32 64 70 6e 6e 31 64 71 6f 6f 32 65 71 6f 6f 33 66 72 70 70 33 66 72 70 70 33 66 72 70 70 } //1 2dpnn1dqoo2eqoo3frpp3frpp3frpp
		$a_01_3 = {76 66 6d 67 75 66 6e 68 76 67 6e 68 77 68 6f 69 77 68 6f 69 77 68 6f 69 } //1 vfmgufnhvgnhwhoiwhoiwhoi
		$a_01_4 = {64 73 6e 63 74 6f 64 74 6f 65 75 70 65 75 70 65 75 70 } //1 dsnctodtoeupeupeup
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}