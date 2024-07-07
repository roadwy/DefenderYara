
rule Trojan_Win32_Qukart_ASJ_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {65 70 76 4c 6f 51 76 4e 46 50 } //1 epvLoQvNFP
		$a_01_1 = {69 4c 45 4c 69 6d 70 41 } //1 iLELimpA
		$a_01_2 = {75 57 46 76 4c 54 4f 4d 25 } //1 uWFvLTOM%
		$a_01_3 = {65 44 62 50 56 65 42 4c } //1 eDbPVeBL
		$a_01_4 = {63 55 71 51 48 61 75 57 } //1 cUqQHauW
		$a_01_5 = {44 75 42 72 44 6a 49 65 } //1 DuBrDjIe
		$a_01_6 = {6e 49 66 6e 52 74 43 55 } //1 nIfnRtCU
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}