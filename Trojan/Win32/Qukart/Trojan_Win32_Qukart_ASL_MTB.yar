
rule Trojan_Win32_Qukart_ASL_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {63 6f 48 55 4c 6b 5a 69 } //1 coHULkZi
		$a_01_1 = {65 4b 7a 64 72 67 57 6c } //1 eKzdrgWl
		$a_01_2 = {6e 62 64 44 70 6e 77 6b } //1 nbdDpnwk
		$a_01_3 = {42 73 6d 54 7a 6e 6b 4e } //1 BsmTznkN
		$a_01_4 = {68 79 4f 49 5a 54 76 79 } //1 hyOIZTvy
		$a_01_5 = {59 6c 6e 77 4c 53 49 73 41 } //1 YlnwLSIsA
		$a_01_6 = {53 52 72 72 68 4d 6c 73 } //1 SRrrhMls
		$a_01_7 = {4f 45 6d 4d 6d 67 76 75 } //1 OEmMmgvu
		$a_01_8 = {75 4a 63 6c 78 50 41 67 } //1 uJclxPAg
		$a_01_9 = {76 73 78 51 47 79 4b 4f } //1 vsxQGyKO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}