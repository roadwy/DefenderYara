
rule Trojan_Win32_Bazar_GA_MTB{
	meta:
		description = "Trojan:Win32/Bazar.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c } //C:\ProgramData\  01 00 
		$a_80_1 = {50 4f 53 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //POST %s HTTP/1.1  01 00 
		$a_80_2 = {48 6f 73 74 3a 20 25 73 } //Host: %s  01 00 
		$a_80_3 = {50 72 61 67 6d 61 3a 20 6e 6f 2d 63 61 63 68 65 } //Pragma: no-cache  01 00 
		$a_80_4 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a 20 25 64 } //Content-Length: %d  01 00 
		$a_80_5 = {68 74 74 70 3a 2f 2f 63 61 6c 6c 32 2e 78 79 7a 2f } //http://call2.xyz/  00 00 
	condition:
		any of ($a_*)
 
}