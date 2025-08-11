
rule Trojan_Win32_LummaStealer_RPM_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {69 0c b7 95 e9 d1 5b 89 cd c1 ed 18 31 cd 69 cd 95 e9 d1 5b 69 d2 95 e9 d1 5b 31 ca 69 4c b7 04 95 e9 d1 5b 89 cd c1 ed 18 31 cd 69 cd 95 e9 d1 5b 69 d2 95 e9 d1 5b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_LummaStealer_RPM_MTB_2{
	meta:
		description = "Trojan:Win32/LummaStealer.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_03_0 = {40 00 00 e0 2e 72 73 72 63 00 00 00 ?? ?? 00 00 ?? ?? 00 00 00 06 00 00 00 60 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 2e 69 64 61 74 61 20 20 00 20 00 00 00 80 00 00 00 02 00 00 00 66 00 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0 } //10
		$a_01_1 = {49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 64 00 65 00 66 00 4f 00 66 00 66 00 2e 00 65 00 78 00 65 00 } //10
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 57 69 6e 4c 69 63 65 6e 73 65 } //1 Software\WinLicense
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=21
 
}