
rule Trojan_BAT_Keylogger_EY_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.EY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {02 72 cf 09 00 70 12 00 fe 16 28 00 00 01 6f 3c 00 00 0a 72 d5 09 00 70 28 3d 00 00 0a 28 1f 00 00 06 00 38 8b 00 00 00 02 72 db 09 00 70 28 1f 00 00 06 00 2b 7d 02 72 df 09 00 70 28 1f 00 00 06 00 2b 6f 02 72 e3 09 00 70 28 1f 00 00 06 00 2b 61 17 13 12 dd b2 00 00 00 28 16 00 00 06 13 0a 11 0a 12 0b 28 19 00 00 06 13 0c 20 00 01 00 00 8d 5a 00 00 01 13 0d 11 0d 28 18 00 00 06 26 11 0c 28 1a 00 00 06 13 0e 73 78 00 00 0a } //1
		$a_01_1 = {6b 00 65 00 79 00 6c 00 6f 00 67 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 keylog.Properties.Resources
		$a_01_2 = {4b 00 65 00 79 00 4c 00 2e 00 68 00 74 00 6d 00 6c 00 } //1 KeyL.html
		$a_01_3 = {6b 00 68 00 61 00 6c 00 65 00 64 00 30 00 35 00 39 00 36 00 40 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //1 khaled0596@gmail.com
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}