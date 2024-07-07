
rule Trojan_Win64_LummaStealer_KAA_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 68 6f 73 65 69 6e 74 72 6f 64 75 63 74 6f 72 79 2e 65 78 65 } //1 thoseintroductory.exe
		$a_01_1 = {63 61 6c 6c 63 75 73 74 6f 6d 65 72 70 72 6f 2e 65 78 65 } //1 callcustomerpro.exe
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //1 Software\Microsoft\Windows\CurrentVersion\RunOnce
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}