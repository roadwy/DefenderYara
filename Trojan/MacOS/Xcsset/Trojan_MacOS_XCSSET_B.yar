
rule Trojan_MacOS_XCSSET_B{
	meta:
		description = "Trojan:MacOS/XCSSET.B,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5f 54 74 43 43 [0-10] 64 [0-02] 57 65 62 53 6f 63 6b 65 74 31 30 57 53 52 65 73 70 6f 6e 73 65 } //1
		$a_01_1 = {64 2f 57 6f 72 6b 65 72 2e 73 77 69 66 74 } //1 d/Worker.swift
		$a_03_2 = {48 b8 50 61 67 65 2e 67 65 74 48 89 ?? ?? 48 b8 43 6f 6f 6b 69 65 73 ef } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}