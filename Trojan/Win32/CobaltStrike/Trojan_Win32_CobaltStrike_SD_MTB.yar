
rule Trojan_Win32_CobaltStrike_SD_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_81_0 = {63 6f 75 6c 64 20 6e 6f 74 20 72 75 6e 20 63 6f 6d 6d 61 6e 64 20 28 77 2f 20 74 6f 6b 65 6e 29 20 62 65 63 61 75 73 65 20 6f 66 20 69 74 73 20 6c 65 6e 67 74 68 20 6f 66 20 25 64 20 62 79 74 65 73 21 } //1 could not run command (w/ token) because of its length of %d bytes!
		$a_81_1 = {63 6f 75 6c 64 20 6e 6f 74 20 73 70 61 77 6e 20 25 73 20 28 74 6f 6b 65 6e 29 3a 20 25 64 } //1 could not spawn %s (token): %d
		$a_81_2 = {49 27 6d 20 61 6c 72 65 61 64 79 20 69 6e 20 53 4d 42 20 6d 6f 64 65 } //1 I'm already in SMB mode
		$a_81_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 70 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 22 25 73 22 } //1 powershell -nop -exec bypass -EncodedCommand "%s"
		$a_01_4 = {54 00 68 00 72 00 65 00 61 00 74 00 5f 00 53 00 6f 00 6e 00 61 00 72 00 } //65526 Threat_Sonar
		$a_03_5 = {73 6f 6e 61 72 5f 6c 65 76 65 6c 90 02 04 6d 61 6c 77 61 72 65 5f 66 61 6d 69 6c 79 90 00 } //65526
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*65526+(#a_03_5  & 1)*65526) >=4
 
}