
rule Backdoor_BAT_Webshell_MBIH_MTB{
	meta:
		description = "Backdoor:BAT/Webshell.MBIH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {64 00 69 00 66 00 6a 00 61 00 66 00 65 00 62 00 00 05 62 00 68 00 00 0d 64 00 65 00 65 00 61 00 63 00 61 00 00 05 6a 00 64 00 00 09 64 00 62 00 65 00 63 00 00 09 66 } //1
		$a_01_1 = {70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 00 09 4c 00 6f 00 61 00 64 00 00 05 4c 00 59 } //1
		$a_01_2 = {47 00 63 00 2f 00 49 00 65 00 4b 00 78 00 6d 00 46 00 32 00 62 00 77 00 54 00 5a 00 39 00 7a 00 52 00 58 00 2b 00 34 00 74 00 6f 00 73 00 55 00 6a 00 41 00 53 00 69 00 } //1 Gc/IeKxmF2bwTZ9zRX+4tosUjASi
		$a_01_3 = {7e 00 2f 00 31 00 32 00 33 00 34 00 2e 00 61 00 73 00 70 00 78 00 } //1 ~/1234.aspx
		$a_01_4 = {7e 00 2f 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 2e 00 61 00 73 00 70 00 78 00 } //1 ~/Service.aspx
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_6 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}