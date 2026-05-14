
rule Trojan_MacOS_Crosdomd_A_MTB{
	meta:
		description = "Trojan:MacOS/Crosdomd.A!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 00 75 00 72 00 6c 00 20 00 2d 00 6f 00 } //1 curl -o
		$a_01_1 = {63 00 6f 00 6d 00 2e 00 61 00 70 00 70 00 6c 00 65 00 2e 00 61 00 63 00 74 00 2e 00 6d 00 6f 00 6e 00 64 00 20 00 } //10 com.apple.act.mond 
		$a_01_2 = {73 00 66 00 72 00 63 00 6c 00 61 00 6b 00 2e 00 63 00 6f 00 6d 00 } //10 sfrclak.com
		$a_01_3 = {63 00 68 00 6d 00 6f 00 64 00 20 00 37 00 37 00 30 00 } //1 chmod 770
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1) >=22
 
}