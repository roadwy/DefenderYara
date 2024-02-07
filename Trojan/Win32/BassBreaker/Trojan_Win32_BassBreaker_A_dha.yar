
rule Trojan_Win32_BassBreaker_A_dha{
	meta:
		description = "Trojan:Win32/BassBreaker.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 2e 00 2e 00 5c 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 } //01 00  \..\Management.dll
		$a_01_1 = {5c 00 2e 00 2e 00 5c 00 4c 00 6f 00 67 00 67 00 69 00 6e 00 67 00 50 00 6c 00 61 00 74 00 66 00 6f 00 72 00 6d 00 2e 00 64 00 6c 00 6c 00 } //01 00  \..\LoggingPlatform.dll
		$a_01_2 = {5c 00 2e 00 2e 00 5c 00 63 00 6f 00 6e 00 66 00 69 00 67 00 5c 00 43 00 6f 00 6e 00 66 00 69 00 67 00 2e 00 64 00 61 00 74 00 } //01 00  \..\config\Config.dat
		$a_01_3 = {5c 00 46 00 69 00 6c 00 65 00 43 00 6f 00 41 00 75 00 74 00 68 00 2e 00 65 00 78 00 65 00 } //00 00  \FileCoAuth.exe
	condition:
		any of ($a_*)
 
}