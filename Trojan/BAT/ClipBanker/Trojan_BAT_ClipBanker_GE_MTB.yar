
rule Trojan_BAT_ClipBanker_GE_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 0d 00 00 "
		
	strings :
		$a_80_0 = {43 6c 69 70 70 65 72 } //Clipper  10
		$a_80_1 = {43 6c 69 70 62 6f 61 72 64 } //Clipboard  1
		$a_80_2 = {52 65 67 65 78 } //Regex  1
		$a_80_3 = {42 61 6e 6b 65 72 } //Banker  1
		$a_80_4 = {42 69 74 63 6f 69 6e } //Bitcoin  1
		$a_80_5 = {52 69 70 70 6c 65 } //Ripple  1
		$a_80_6 = {50 61 79 65 65 72 } //Payeer  1
		$a_80_7 = {5a 63 61 73 68 } //Zcash  1
		$a_80_8 = {73 63 68 74 61 73 6b 73 } //schtasks  1
		$a_80_9 = {53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 57 69 6e 33 32 5f 43 6f 6d 70 75 74 65 72 53 79 73 74 65 6d } //SELECT * FROM Win32_ComputerSystem  1
		$a_80_10 = {76 6d 77 61 72 65 } //vmware  1
		$a_80_11 = {41 6e 74 69 56 6d } //AntiVm  1
		$a_80_12 = {49 50 4c 6f 67 67 65 72 } //IPLogger  1
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=17
 
}