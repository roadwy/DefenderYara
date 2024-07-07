
rule Trojan_Linux_SaltWater_B_MTB{
	meta:
		description = "Trojan:Linux/SaltWater.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6d 6f 64 5f 75 64 70 } //1 mod_udp
		$a_00_1 = {6c 69 62 62 69 6e 64 73 68 65 6c 6c 2e 73 6f } //1 libbindshell.so
		$a_00_2 = {55 70 6c 6f 61 64 43 68 61 6e 6e 65 6c } //1 UploadChannel
		$a_00_3 = {67 65 74 68 6f 73 74 62 79 6e 61 6d 65 } //1 gethostbyname
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}