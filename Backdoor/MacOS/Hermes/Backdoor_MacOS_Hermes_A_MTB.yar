
rule Backdoor_MacOS_Hermes_A_MTB{
	meta:
		description = "Backdoor:MacOS/Hermes.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 65 72 6d 65 73 2f 68 74 74 70 2e 73 77 69 66 74 } //1 Hermes/http.swift
		$a_01_1 = {48 65 72 6d 65 73 2f 53 77 43 72 79 70 74 2e 73 77 69 66 74 } //1 Hermes/SwCrypt.swift
		$a_01_2 = {48 65 72 6d 65 73 2f 63 72 79 70 74 6f 2e 73 77 69 66 74 } //1 Hermes/crypto.swift
		$a_03_3 = {ff 83 01 d1 f8 5f 02 a9 f6 57 03 a9 f4 4f 04 a9 fd 7b 05 a9 fd 43 01 91 15 d8 43 a9 c8 ee 78 d3 a1 be 40 92 df 02 43 f2 29 00 88 9a a9 ?? ?? ?? f3 03 00 aa 96 2b ?? ?? 36 03 ?? ?? b5 2c ?? ?? c8 ee 40 92 00 81 00 91 } //5
		$a_01_4 = {40 33 40 f9 a8 4c 8e d2 48 ee ad f2 48 0e c0 f2 09 a0 fc d2 48 a7 05 a9 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*5+(#a_01_4  & 1)*5) >=11
 
}