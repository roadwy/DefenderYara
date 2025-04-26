
rule Trojan_Win32_RasDialer_O{
	meta:
		description = "Trojan:Win32/RasDialer.O,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {47 6c 6f 44 69 61 6c } //10 GloDial
		$a_01_1 = {25 63 25 63 25 63 43 55 52 52 45 4e 54 3a 20 50 61 79 73 3a 20 25 73 2c 20 49 44 3a 20 25 73 20 25 63 25 63 25 63 55 52 4c 3a 20 25 73 25 63 25 63 25 63 } //1 %c%c%cCURRENT: Pays: %s, ID: %s %c%c%cURL: %s%c%c%c
		$a_01_2 = {25 63 25 63 25 63 43 75 73 74 6f 6d 65 72 20 53 75 70 70 6f 72 74 2f 53 75 70 70 6f 72 74 20 43 6c 69 65 6e 74 3a 20 25 63 25 63 25 63 } //1 %c%c%cCustomer Support/Support Client: %c%c%c
		$a_01_3 = {59 4f 55 20 41 52 45 20 43 4f 4e 4e 45 43 54 45 44 20 46 4f 52 20 25 73 20 4d 49 4e 55 54 45 53 } //1 YOU ARE CONNECTED FOR %s MINUTES
		$a_01_4 = {26 67 63 73 6b 69 74 3d 25 73 26 67 63 73 6c 61 6e 67 3d 25 73 26 67 63 73 63 6f 75 6e 74 72 79 3d 25 73 } //1 &gcskit=%s&gcslang=%s&gcscountry=%s
		$a_01_5 = {54 68 65 20 70 72 69 63 65 20 66 6f 72 20 74 68 69 73 20 63 61 6c 6c 20 77 69 6c 6c 20 62 65 } //1 The price for this call will be
		$a_01_6 = {25 63 25 63 25 63 43 55 53 54 4f 4d 45 52 20 53 45 52 56 49 43 45 20 28 46 4f 52 20 55 4b 20 4f 4e 4c 59 29 3a 20 30 38 37 30 20 38 30 30 20 38 37 36 30 } //1 %c%c%cCUSTOMER SERVICE (FOR UK ONLY): 0870 800 8760
		$a_01_7 = {75 64 70 69 6e 66 6f 2e 63 72 65 61 6e 65 74 2e 63 6f 6d } //1 udpinfo.creanet.com
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=14
 
}