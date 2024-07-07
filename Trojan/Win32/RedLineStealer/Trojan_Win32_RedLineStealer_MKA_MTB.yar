
rule Trojan_Win32_RedLineStealer_MKA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {fc b8 3b 2d 0b 00 01 45 fc 90 0a 12 00 a1 90 01 04 89 45 90 02 0a 8b 45 fc 8a 04 38 8b 0d 90 01 04 88 04 39 83 3d 90 01 04 44 75 90 01 01 56 8d 85 b4 f6 ff ff 50 ff 15 90 01 04 47 3b 3d 48 16 43 00 72 90 00 } //1
		$a_01_1 = {72 75 6e 65 78 6f 62 6f 7a 65 7a } //1 runexobozez
		$a_01_2 = {7a 6f 70 69 76 2e 74 78 74 } //1 zopiv.txt
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}