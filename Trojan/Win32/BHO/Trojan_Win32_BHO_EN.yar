
rule Trojan_Win32_BHO_EN{
	meta:
		description = "Trojan:Win32/BHO.EN,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects
		$a_01_1 = {68 74 2a 2c 2b 2c 5e 61 62 2a 74 70 3a 2f 2a 2c 2b 2c 5e 61 62 2a 2f } //3 ht*,+,^ab*tp:/*,+,^ab*/
		$a_01_2 = {2e 65 2a 2c 2b 2c 5e 61 62 2a 78 2a 2c 2b 2c 5e 61 62 2a 65 } //4 .e*,+,^ab*x*,+,^ab*e
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4) >=8
 
}