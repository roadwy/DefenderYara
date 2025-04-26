
rule Trojan_Win32_Phyiost_A{
	meta:
		description = "Trojan:Win32/Phyiost.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {66 ad 66 35 ?? ?? 66 ab 4e 4f 66 81 3e ?? ?? 75 ef } //2
		$a_00_1 = {c1 c2 03 32 10 40 80 38 00 75 f5 57 39 17 75 14 } //1
		$a_00_2 = {73 72 73 76 63 2e 64 6c 6c 00 53 65 72 76 69 63 65 4d 61 69 6e } //1
		$a_00_3 = {61 63 63 65 70 74 3a 20 2a 2f 2a } //1 accept: */*
		$a_00_4 = {7d 61 61 65 2f 3a 3a } //1 }aae/::
	condition:
		((#a_03_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}