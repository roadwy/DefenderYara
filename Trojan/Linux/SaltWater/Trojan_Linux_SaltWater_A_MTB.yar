
rule Trojan_Linux_SaltWater_A_MTB{
	meta:
		description = "Trojan:Linux/SaltWater.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {71 75 69 74 0d 0a 00 00 00 33 8c 25 3d 9c 17 70 08 f9 0c 1a 41 71 55 36 1a 5c 4b 8d 29 7e 0d 78 } //1
		$a_01_1 = {55 70 6c 6f 61 64 43 68 61 6e 6e 65 6c } //1 UploadChannel
		$a_01_2 = {6c 69 62 62 69 6e 64 73 68 65 6c 6c 2e 73 6f } //1 libbindshell.so
		$a_01_3 = {43 6f 6e 6e 65 63 74 65 64 32 56 70 73 } //1 Connected2Vps
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}