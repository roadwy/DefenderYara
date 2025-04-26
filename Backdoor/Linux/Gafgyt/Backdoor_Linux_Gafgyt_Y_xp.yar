
rule Backdoor_Linux_Gafgyt_Y_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.Y!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 51 52 4f 51 52 54 51 52 4b 51 52 49 51 52 4c 51 52 4c } //1 BQROQRTQRKQRIQRLQRL
		$a_01_1 = {2f 51 52 75 51 52 73 51 52 72 51 52 2f 51 52 73 51 52 62 51 52 69 51 52 6e 51 52 2f 51 52 64 51 52 72 51 52 6f 51 52 70 51 52 62 51 52 65 51 52 61 51 52 72 } //1 /QRuQRsQRrQR/QRsQRbQRiQRnQR/QRdQRrQRoQRpQRbQReQRaQRr
		$a_01_2 = {4b 51 52 69 51 52 6c 51 52 6c 51 52 69 51 52 6e 51 52 67 51 52 20 51 52 42 51 52 6f 51 52 74 51 52 73 } //1 KQRiQRlQRlQRiQRnQRgQR QRBQRoQRtQRs
		$a_01_3 = {42 51 52 75 51 52 73 51 52 79 51 52 42 51 52 6f 51 52 78 } //1 BQRuQRsQRyQRBQRoQRx
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}