
rule PWS_BAT_Bahmajip_A{
	meta:
		description = "PWS:BAT/Bahmajip.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 08 00 00 "
		
	strings :
		$a_01_0 = {20 4b 02 00 00 6f } //1
		$a_00_1 = {20 00 2f 00 20 00 50 00 61 00 73 00 73 00 3a 00 20 00 } //1  / Pass: 
		$a_00_2 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 smtp.gmail.com
		$a_01_3 = {4d 61 69 6c 41 64 64 72 65 73 73 00 73 65 74 5f 46 72 6f 6d 00 4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e 00 67 65 74 5f 54 6f 00 73 65 74 5f 53 75 62 6a 65 63 74 00 67 65 74 5f 54 65 78 74 00 43 6f 6e 63 61 74 00 73 65 74 5f 42 6f 64 79 00 73 65 74 5f 50 6f 72 74 00 73 65 74 5f 45 6e 61 62 6c 65 53 73 6c } //1
		$a_01_4 = {50 00 6c 00 65 00 61 00 73 00 65 00 20 00 70 00 75 00 74 00 20 00 79 00 6f 00 75 00 72 00 20 00 65 00 6d 00 61 00 69 00 6c 00 } //1 Please put your email
		$a_01_5 = {4e 00 6f 00 20 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 66 00 6f 00 75 00 6e 00 64 00 21 00 } //1 No Password found!
		$a_01_6 = {45 00 72 00 72 00 6f 00 72 00 21 00 20 00 20 00 50 00 6c 00 65 00 61 00 73 00 65 00 20 00 65 00 6e 00 74 00 65 00 72 00 20 00 61 00 20 00 63 00 6f 00 72 00 72 00 65 00 63 00 74 00 20 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 20 00 61 00 6e 00 64 00 20 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 Error!  Please enter a correct username and password
		$a_01_7 = {4d 61 69 6c 41 64 64 72 65 73 73 43 6f 6c 6c 65 63 74 69 6f 6e 00 } //1 慍汩摁牤獥䍳汯敬瑣潩n
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=4
 
}