
rule Trojan_MacOS_WindTape_A{
	meta:
		description = "Trojan:MacOS/WindTape.A,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {45 31 ff 31 ff be 01 00 00 00 ba 01 00 00 00 41 b8 08 00 00 00 48 89 d9 4c 8d 8d b8 fb ff ff 48 8d 85 c8 fb ff ff 50 68 00 04 00 00 48 8d 85 d0 fb ff ff 50 41 54 41 56 e8 cb 3b 00 00 } //2
		$a_00_1 = {25 40 2f 25 40 2e 6a 70 67 } //1 %@/%@.jpg
		$a_00_2 = {47 65 6e 72 61 74 65 44 65 76 69 63 65 4e 61 6d 65 } //1 GenrateDeviceName
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=4
 
}