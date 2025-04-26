
rule Trojan_Win32_Qakbot_BO_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 70 65 74 61 6c 6f 69 64 } //1 apetaloid
		$a_01_1 = {6c 61 64 79 6b 69 6e 64 } //1 ladykind
		$a_01_2 = {6f 76 65 72 69 6e 64 75 6c 67 65 } //1 overindulge
		$a_01_3 = {73 70 69 72 6f 6d 65 74 65 72 } //1 spirometer
		$a_01_4 = {74 6f 77 6e 6c 65 73 73 } //1 townless
		$a_01_5 = {7a 61 70 61 72 6f 61 6e } //1 zaparoan
		$a_01_6 = {67 72 61 62 65 6e } //1 graben
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}