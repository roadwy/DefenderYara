
rule Backdoor_Linux_Mirai_JU_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.JU!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6d 20 2d 66 20 72 6f 6e 64 6f 2e 6d 69 70 73 65 6c } //1 rm -f rondo.mipsel
		$a_03_1 = {77 67 65 74 20 68 74 74 70 3a 2f 2f [0-12] 2e 64 64 6e 73 2e 6e 65 74 2f 72 6f 6e 64 6f 2e [0-07] 3b 63 68 6d 6f 64 20 37 37 37 20 72 6f 6e 64 6f 2e [0-07] 3b 2e 2f 72 6f 6e 64 6f 2e [0-07] 20 73 65 6c 66 72 65 70 2e 6c 62 6c 69 6e 6b 2e 6d 69 70 73 65 6c } //1
		$a_01_2 = {2e 2f 72 6f 6e 64 6f 2e 70 69 64 } //1 ./rondo.pid
		$a_01_3 = {6f 70 65 6e 76 70 6e 63 72 79 70 74 74 63 70 } //1 openvpncrypttcp
		$a_01_4 = {6f 70 65 6e 76 70 6e 63 72 79 70 74 } //1 openvpncrypt
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}