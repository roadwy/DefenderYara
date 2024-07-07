
rule Trojan_Win32_Barkiofork_dha{
	meta:
		description = "Trojan:Win32/Barkiofork!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 55 53 45 52 50 52 4f 46 49 4c 45 25 5c 54 65 6d 70 5c 7e 49 53 55 4e 33 32 2e 45 58 45 } //1 %USERPROFILE%\Temp\~ISUN32.EXE
		$a_01_1 = {2f 32 30 31 31 2f 6e 33 32 35 34 32 33 2e 73 68 74 6d 6c 3f } //1 /2011/n325423.shtml?
		$a_01_2 = {4d 41 43 20 41 64 64 72 65 73 73 3a 20 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 2d 25 30 32 58 } //1 MAC Address: %02X-%02X-%02X-%02X-%02X-%02X
		$a_01_3 = {44 72 69 76 65 20 53 65 72 69 61 6c 20 4e 75 6d 62 65 72 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 3a 20 5b 25 73 5d } //1 Drive Serial Number_______________: [%s]
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}