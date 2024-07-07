
rule Trojan_MacOS_NukeSped_A_MTB{
	meta:
		description = "Trojan:MacOS/NukeSped.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 65 61 73 74 67 6f 63 2e 63 6f 6d } //2 beastgoc.com
		$a_00_1 = {25 73 2f 67 72 65 70 6d 6f 6e 75 78 2e 70 68 70 } //1 %s/grepmonux.php
		$a_00_2 = {89 ce 83 e6 0f 42 8a 14 06 30 14 0f 48 ff c1 48 39 c8 75 ec } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}