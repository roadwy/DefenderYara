
rule Backdoor_Linux_Mirai_DP_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.DP!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 74 6d 70 2f 63 6f 6e 64 69 6e 65 74 77 6f 72 6b } //1 /tmp/condinetwork
		$a_01_1 = {2f 76 61 72 2f 63 6f 6e 64 69 62 6f 74 } //1 /var/condibot
		$a_01_2 = {7c 08 02 a6 94 21 ff f0 90 01 00 14 80 03 00 0c 2f 80 00 01 41 9e 00 2c 41 bd 00 10 2f 80 00 00 41 9e 00 50 48 00 00 14 2f 80 00 02 41 9e 00 54 2f 80 00 03 41 9e 00 6c 39 20 00 16 48 00 00 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}