
rule Trojan_Win32_Koadic_A_attk{
	meta:
		description = "Trojan:Win32/Koadic.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 [0-0f] 68 00 74 00 74 00 70 00 } //1
		$a_02_1 = {6d 00 73 00 68 00 74 00 6d 00 6c 00 2c 00 [0-30] 52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1
		$a_00_2 = {3d 00 3b 00 5c 00 } //1 =;\
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Koadic_A_attk_2{
	meta:
		description = "Trojan:Win32/Koadic.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_02_0 = {5c 00 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 2e 00 65 00 78 00 65 00 [0-30] 72 00 65 00 67 00 73 00 76 00 72 00 33 00 32 00 } //1
		$a_00_1 = {20 00 2f 00 73 00 20 00 } //1  /s 
		$a_00_2 = {20 00 2f 00 75 00 20 00 } //1  /u 
		$a_00_3 = {20 00 2f 00 6e 00 20 00 } //1  /n 
		$a_00_4 = {20 00 2f 00 69 00 3a 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 } //1  /i:http://
		$a_02_5 = {3d 00 3b 00 [0-10] 73 00 63 00 72 00 6f 00 62 00 6a 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Koadic_A_attk_3{
	meta:
		description = "Trojan:Win32/Koadic.A!attk,SIGNATURE_TYPE_CMDHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_00_0 = {5c 00 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 00 00 } //1
		$a_00_1 = {20 00 6a 00 61 00 76 00 61 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 } //1  javascript:
		$a_02_2 = {5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-08] 2c 00 } //1
		$a_00_3 = {52 00 75 00 6e 00 48 00 54 00 4d 00 4c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 } //1 RunHTMLApplication
		$a_00_4 = {41 00 63 00 74 00 69 00 76 00 65 00 58 00 4f 00 62 00 6a 00 65 00 63 00 74 00 28 00 } //1 ActiveXObject(
		$a_00_5 = {4d 00 73 00 78 00 6d 00 6c 00 32 00 2e 00 53 00 65 00 72 00 76 00 65 00 72 00 58 00 4d 00 4c 00 48 00 54 00 54 00 50 00 } //1 Msxml2.ServerXMLHTTP
		$a_00_6 = {2e 00 6f 00 70 00 65 00 6e 00 28 00 } //1 .open(
		$a_00_7 = {2e 00 73 00 65 00 6e 00 64 00 28 00 29 00 3b 00 } //1 .send();
		$a_00_8 = {65 00 76 00 61 00 6c 00 28 00 } //1 eval(
		$a_00_9 = {2e 00 72 00 65 00 73 00 70 00 6f 00 6e 00 73 00 65 00 54 00 65 00 78 00 74 00 29 00 3b 00 } //1 .responseText);
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}