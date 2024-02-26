
rule Trojan_Win32_Zusy_ASF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 68 01 03 00 80 6a 00 68 02 00 00 00 68 02 00 03 00 68 26 0e 01 16 68 01 00 01 52 68 03 00 00 00 b8 02 00 00 00 bb } //01 00 
		$a_01_1 = {6b 6c 6a 73 7a 64 66 79 72 77 65 6f 6e 33 34 76 39 33 34 35 2c 6f 69 72 65 75 } //01 00  kljszdfyrweon34v9345,oireu
		$a_01_2 = {77 73 64 6c 71 2e 63 6f 6d 2f 77 67 2f 77 6c 62 62 2e 74 78 74 } //01 00  wsdlq.com/wg/wlbb.txt
		$a_01_3 = {7c 79 61 6e 63 68 69 63 61 6f 7a 75 6f 7c } //00 00  |yanchicaozuo|
	condition:
		any of ($a_*)
 
}