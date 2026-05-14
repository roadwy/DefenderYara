
rule Trojan_Linux_ProfileMod_B{
	meta:
		description = "Trojan:Linux/ProfileMod.B,SIGNATURE_TYPE_CMDHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_00_0 = {65 00 63 00 68 00 6f 00 20 00 } //10 echo 
		$a_00_1 = {73 00 75 00 64 00 6f 00 20 00 } //10 sudo 
		$a_00_2 = {20 00 69 00 6e 00 73 00 6d 00 6f 00 64 00 20 00 } //10  insmod 
		$a_00_3 = {2e 00 62 00 61 00 73 00 68 00 5f 00 70 00 72 00 6f 00 66 00 69 00 6c 00 65 00 20 00 } //10 .bash_profile 
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10) >=40
 
}