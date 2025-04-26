
rule Trojan_Win32_Tarifarch_Z{
	meta:
		description = "Trojan:Win32/Tarifarch.Z,SIGNATURE_TYPE_PEHSTR,19 00 19 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 5a 69 70 20 32 30 31 31 } //10 WinZip 2011
		$a_01_1 = {52 55 53 53 49 41 4e 5f 43 48 41 52 53 45 54 } //10 RUSSIAN_CHARSET
		$a_01_2 = {74 65 78 74 50 68 6f 6e 65 50 72 65 66 69 78 } //1 textPhonePrefix
		$a_01_3 = {70 52 65 62 69 6c 6c 73 } //1 pRebills
		$a_01_4 = {6c 61 62 65 6c 53 6d 73 49 6e 66 6f 43 6f 75 6e 74 } //1 labelSmsInfoCount
		$a_01_5 = {6c 61 62 65 6c 53 6d 73 4e 75 6d 62 65 72 } //1 labelSmsNumber
		$a_01_6 = {6c 61 62 65 6c 53 6d 73 54 65 78 74 } //1 labelSmsText
		$a_01_7 = {63 6f 6e 66 69 72 6d 61 74 69 6f 6e 43 6f 64 65 } //1 confirmationCode
		$a_01_8 = {6c 53 77 69 74 63 68 54 6f 4e 6f 72 6d 61 6c 53 6d 73 4d 6f 64 65 31 } //1 lSwitchToNormalSmsMode1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=25
 
}