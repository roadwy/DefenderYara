
rule Trojan_Win32_Ekstak_ASGR_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {56 57 6a 00 ff 15 ?? ?? 65 00 6a 00 ff 15 ?? ?? 65 00 8b f0 ff 15 ?? ?? 65 00 6a 5a 56 a3 ?? ?? 65 00 ff 15 ?? ?? 65 00 56 6a 00 8b f8 ff 15 ?? ?? 65 00 8b c7 5f 5e c3 } //3
		$a_03_1 = {56 57 6a 00 ff 15 ?? ?? 65 00 8b f0 6a 5a 56 ff 15 ?? ?? 65 00 56 6a 00 8b f8 ff 15 ?? ?? 65 00 8b c7 5f 5e c3 } //3
		$a_01_2 = {45 00 78 00 74 00 72 00 65 00 6d 00 65 00 5a 00 2d 00 49 00 50 00 2e 00 65 00 78 00 65 00 } //1 ExtremeZ-IP.exe
		$a_01_3 = {56 57 e8 c9 53 fb ff 8b f0 e9 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}