
rule Trojan_BAT_SnakeKeylogger_NEB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 03 11 01 11 03 11 01 8e 69 5d 91 11 04 11 03 91 61 d2 9c } //1
		$a_01_1 = {62 00 69 00 6e 00 5f 00 4e 00 6e 00 71 00 79 00 63 00 63 00 6a 00 75 00 2e 00 6a 00 70 00 67 00 } //1 bin_Nnqyccju.jpg
		$a_01_2 = {48 00 62 00 77 00 6c 00 75 00 61 00 7a 00 73 00 69 00 } //1 Hbwluazsi
		$a_01_3 = {4c 00 7a 00 63 00 77 00 6f 00 7a 00 6c 00 67 00 6e 00 63 00 76 00 6e 00 72 00 79 00 62 00 76 00 63 00 6b 00 6a 00 74 00 74 00 } //1 Lzcwozlgncvnrybvckjtt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}