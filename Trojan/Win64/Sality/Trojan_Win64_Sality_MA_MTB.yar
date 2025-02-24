
rule Trojan_Win64_Sality_MA_MTB{
	meta:
		description = "Trojan:Win64/Sality.MA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 72 75 73 74 65 64 49 6e 73 74 61 6c 6c 65 72 } //1 TrustedInstaller
		$a_01_1 = {31 00 30 00 2e 00 30 00 2e 00 31 00 37 00 31 00 33 00 34 00 2e 00 31 00 33 00 30 00 34 00 } //1 10.0.17134.1304
		$a_01_2 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4d 00 6f 00 64 00 75 00 6c 00 65 00 73 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 } //1 Windows Modules Installer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}