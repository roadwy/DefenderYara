
rule Trojan_BAT_FormBook_DPUF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.DPUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {49 00 63 00 65 00 43 00 72 00 65 00 61 00 6d 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //01 00  IceCreamManager
		$a_01_1 = {48 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 } //01 00  HController
		$a_01_2 = {33 00 38 00 46 00 34 00 57 00 50 00 39 00 45 00 34 00 48 00 48 00 38 00 35 00 38 00 46 00 41 00 53 00 43 00 4a 00 53 00 42 00 35 00 } //01 00  38F4WP9E4HH858FASCJSB5
		$a_01_3 = {49 00 6e 00 76 00 6f 00 6b 00 65 00 } //01 00  Invoke
		$a_01_4 = {61 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //01 00  a____________________
		$a_01_5 = {57 44 43 57 43 46 44 52 52 } //01 00  WDCWCFDRR
		$a_01_6 = {54 6f 49 6e 74 33 32 } //01 00  ToInt32
		$a_01_7 = {47 65 74 4d 65 74 68 6f 64 73 } //00 00  GetMethods
	condition:
		any of ($a_*)
 
}