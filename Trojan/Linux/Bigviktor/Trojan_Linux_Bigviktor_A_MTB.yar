
rule Trojan_Linux_Bigviktor_A_MTB{
	meta:
		description = "Trojan:Linux/Bigviktor.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 74 70 40 65 78 61 6d 70 6c 65 2e 63 6f 6d } //1 ftp@example.com
		$a_00_1 = {25 73 2f 73 2e 6a 70 65 67 } //1 %s/s.jpeg
		$a_00_2 = {2f 6d 61 6c 65 2e 6a 70 65 67 } //1 /male.jpeg
		$a_00_3 = {25 73 2f 69 6d 61 67 65 2e 6a 70 65 67 3f 74 3d 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 26 76 3d 25 64 } //1 %s/image.jpeg?t=%c%c%c%c%c%c%c%c&v=%d
		$a_00_4 = {31 2e 31 2e 31 2e 31 2c 38 2e 38 2e 38 2e 38 } //1 1.1.1.1,8.8.8.8
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}