
rule PWS_BAT_Disstl_AD_MTB{
	meta:
		description = "PWS:BAT/Disstl.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {08 0d 16 13 04 2b 36 09 11 04 9a 73 3b 00 00 0a 6f 3c 00 00 0a 28 3d 00 00 0a 13 05 07 11 05 6f 3e 00 00 0a 13 06 11 06 6f 3f 00 00 0a 2c 08 11 06 6f 40 00 00 0a 0a 11 04 17 58 13 04 11 04 09 8e 69 32 c3 } //2
		$a_01_1 = {47 72 6f 77 74 6f 70 69 61 5f 53 61 76 65 5f 53 74 65 61 6c 65 72 } //1 Growtopia_Save_Stealer
		$a_01_2 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 69 00 6d 00 } //1 taskkill /f /im
		$a_01_3 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 6c 00 69 00 70 00 70 00 65 00 72 00 43 00 6c 00 69 00 70 00 62 00 6f 00 61 00 72 00 64 00 2e 00 74 00 78 00 74 00 } //1 Windows\ClipperClipboard.txt
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}