
rule Trojan_Win32_CryptInject_NEAA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.NEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 05 00 "
		
	strings :
		$a_01_0 = {4e 00 46 00 54 00 51 00 6f 00 32 00 37 00 30 00 55 00 20 00 53 00 75 00 70 00 73 00 75 00 70 00 20 00 53 00 65 00 74 00 75 00 70 00 } //05 00  NFTQo270U Supsup Setup
		$a_01_1 = {53 65 74 75 70 4c 64 72 2e 65 78 65 } //01 00  SetupLdr.exe
		$a_01_2 = {6d 61 63 75 6b 72 61 69 6e 65 } //01 00  macukraine
		$a_01_3 = {63 73 69 73 6f 32 30 32 32 6a 70 } //01 00  csiso2022jp
		$a_01_4 = {6d 61 63 72 6f 6d 61 6e 69 61 } //01 00  macromania
		$a_01_5 = {32 36 2e 30 2e 33 36 30 33 39 2e 37 38 39 39 } //01 00  26.0.36039.7899
		$a_01_6 = {6b 57 69 6e 61 70 69 2e 50 73 41 50 49 } //00 00  kWinapi.PsAPI
	condition:
		any of ($a_*)
 
}