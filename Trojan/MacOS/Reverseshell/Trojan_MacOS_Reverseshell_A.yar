
rule Trojan_MacOS_Reverseshell_A{
	meta:
		description = "Trojan:MacOS/Reverseshell.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 73 00 6f 00 63 00 6b 00 65 00 74 00 28 00 } //1 socket.socket(
		$a_01_1 = {73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 41 00 46 00 5f 00 49 00 4e 00 45 00 54 00 2c 00 73 00 6f 00 63 00 6b 00 65 00 74 00 2e 00 53 00 4f 00 43 00 4b 00 5f 00 53 00 54 00 52 00 45 00 41 00 4d 00 } //1 socket.AF_INET,socket.SOCK_STREAM
		$a_01_2 = {2e 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 28 00 } //1 .connect(
		$a_01_3 = {2e 00 73 00 70 00 61 00 77 00 6e 00 28 00 2f 00 2f 00 62 00 69 00 6e 00 2f 00 2f 00 62 00 61 00 73 00 68 00 } //1 .spawn(//bin//bash
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}