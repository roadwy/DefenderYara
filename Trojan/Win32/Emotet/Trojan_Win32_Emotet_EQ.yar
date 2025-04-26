
rule Trojan_Win32_Emotet_EQ{
	meta:
		description = "Trojan:Win32/Emotet.EQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4e 00 43 00 68 00 72 00 6f 00 6d 00 65 00 4c 00 78 00 61 00 76 00 69 00 65 00 72 00 72 00 70 00 72 00 6f 00 74 00 6f 00 63 00 6f 00 6c 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 39 00 4b 00 61 00 6e 00 64 00 } //1 NChromeLxavierrprotocolGoogle9Kand
		$a_01_1 = {79 00 73 00 77 00 69 00 74 00 63 00 68 00 55 00 70 00 64 00 61 00 74 00 65 00 36 00 6e 00 6a 00 4a 00 59 00 70 00 75 00 62 00 6c 00 69 00 63 00 6c 00 79 00 61 00 70 00 70 00 72 00 6f 00 78 00 69 00 6d 00 61 00 74 00 65 00 6c 00 79 00 } //1 yswitchUpdate6njJYpubliclyapproximately
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}