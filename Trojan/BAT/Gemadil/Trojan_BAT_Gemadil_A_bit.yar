
rule Trojan_BAT_Gemadil_A_bit{
	meta:
		description = "Trojan:BAT/Gemadil.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 43 00 68 00 65 00 63 00 6b 00 56 00 4d 00 } //1 Options.CheckVM
		$a_01_1 = {4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 43 00 68 00 65 00 63 00 6b 00 53 00 61 00 6e 00 64 00 62 00 6f 00 78 00 } //1 Options.CheckSandbox
		$a_01_2 = {4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00 2e 00 55 00 41 00 43 00 42 00 79 00 70 00 61 00 73 00 73 00 } //1 Options.UACBypass
		$a_01_3 = {2f 00 63 00 20 00 63 00 6f 00 70 00 79 00 20 00 22 00 7b 00 30 00 7d 00 22 00 20 00 22 00 7b 00 31 00 7d 00 22 00 } //1 /c copy "{0}" "{1}"
		$a_01_4 = {2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 22 00 22 00 20 00 22 00 7b 00 30 00 7d 00 22 00 } //1 /c start "" "{0}"
		$a_01_5 = {61 00 76 00 70 00 75 00 69 00 00 00 00 00 61 00 76 00 61 00 73 00 74 00 75 00 69 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=5
 
}