
rule Trojan_BAT_KillMBR_SV_MTB{
	meta:
		description = "Trojan:BAT/KillMBR.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 50 43 20 69 73 20 74 72 61 73 68 65 64 20 62 79 20 74 72 6f 6a 61 6e } //1 Your PC is trashed by trojan
		$a_01_1 = {59 6f 75 72 20 50 43 20 69 73 20 74 72 61 73 68 65 64 20 62 79 20 74 72 6f 6a 61 6e 20 4d 42 52 20 48 65 63 6b 65 72 } //1 Your PC is trashed by trojan MBR Hecker
		$a_01_2 = {49 66 20 79 6f 75 20 6c 6f 6f 6b 20 61 74 20 74 68 69 73 20 73 63 72 65 65 6e 2c 20 79 6f 75 20 63 61 6e 6e 6f 74 20 73 74 61 72 74 20 79 6f 75 72 20 4f 53 } //1 If you look at this screen, you cannot start your OS
		$a_01_3 = {52 65 61 73 6f 6e 3a 20 4d 42 52 20 69 73 20 6f 76 65 72 77 72 69 74 65 64 } //1 Reason: MBR is overwrited
		$a_01_4 = {49 20 68 6f 70 65 20 6d 79 20 74 72 6f 6a 61 6e 20 69 73 20 63 6f 6f 6c 21 } //1 I hope my trojan is cool!
		$a_01_5 = {2e 2e 2e 20 61 6e 64 20 79 65 61 68 2c 20 74 68 61 74 27 73 20 61 6c 6c 20 3a 44 } //1 ... and yeah, that's all :D
		$a_01_6 = {59 6f 75 72 20 50 43 20 69 73 20 64 69 65 64 } //1 Your PC is died
		$a_01_7 = {53 61 79 20 67 6f 6f 64 62 79 65 21 20 3a 44 } //1 Say goodbye! :D
		$a_01_8 = {48 65 63 6b 65 72 2e 70 64 62 } //1 Hecker.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}