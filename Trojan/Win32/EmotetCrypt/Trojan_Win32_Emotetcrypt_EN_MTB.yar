
rule Trojan_Win32_Emotetcrypt_EN_MTB{
	meta:
		description = "Trojan:Win32/Emotetcrypt.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_1 = {6c 64 73 6b 6f 69 74 69 70 7a 6c 73 70 68 2e 64 6c 6c } //01 00  ldskoitipzlsph.dll
		$a_81_2 = {65 67 69 6d 73 74 6f 72 66 6d 74 79 63 6f 6d 6b 62 } //01 00  egimstorfmtycomkb
		$a_81_3 = {65 6a 72 69 70 6b 64 68 79 74 6b 7a 78 } //01 00  ejripkdhytkzx
		$a_81_4 = {65 70 7a 78 71 67 6b 71 71 65 72 70 78 77 71 6b } //01 00  epzxqgkqqerpxwqk
		$a_81_5 = {69 6f 67 75 78 6b 66 61 78 6e 68 6b 63 72 78 69 } //01 00  ioguxkfaxnhkcrxi
		$a_81_6 = {67 69 77 6b 68 6e 6a 6c 74 70 2e 64 6c 6c } //01 00  giwkhnjltp.dll
		$a_81_7 = {62 61 68 6b 67 6b 78 6b 64 72 6f 6b 6c 6a } //01 00  bahkgkxkdroklj
		$a_81_8 = {62 6b 61 7a 7a 73 64 70 63 74 70 6d 79 72 61 } //01 00  bkazzsdpctpmyra
		$a_81_9 = {65 77 6f 79 70 77 73 62 64 61 70 6d } //01 00  ewoypwsbdapm
		$a_81_10 = {68 6d 73 65 63 70 63 69 72 75 64 74 70 77 64 72 62 } //00 00  hmsecpcirudtpwdrb
	condition:
		any of ($a_*)
 
}