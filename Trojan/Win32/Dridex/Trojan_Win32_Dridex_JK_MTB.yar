
rule Trojan_Win32_Dridex_JK_MTB{
	meta:
		description = "Trojan:Win32/Dridex.JK!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 69 6e 67 55 6a 75 73 61 67 65 75 78 78 64 65 65 6d 65 64 46 45 76 65 72 79 77 68 65 72 65 } //1 StartingUjusageuxxdeemedFEverywhere
		$a_01_1 = {43 68 72 6f 6d 65 57 65 62 4b 69 74 2c 46 75 39 67 54 68 65 6f 72 77 61 73 76 69 64 65 6f } //1 ChromeWebKit,Fu9gTheorwasvideo
		$a_01_2 = {4e 74 31 65 57 68 65 6e 54 68 69 73 68 73 75 62 6d 69 73 73 69 6f 6e 73 63 68 72 69 73 66 6f 72 } //1 Nt1eWhenThishsubmissionschrisfor
		$a_01_3 = {4f 6d 6e 69 62 6f 78 2e 43 68 72 6f 6d 65 6f 66 4e 56 69 6e 31 39 32 34 41 72 65 61 4e } //1 Omnibox.ChromeofNVin1924AreaN
		$a_01_4 = {6f 66 49 63 6f 6d 6d 75 6e 69 74 79 70 6f 70 75 6c 61 72 52 76 69 73 69 74 65 64 } //1 ofIcommunitypopularRvisited
		$a_01_5 = {70 72 6f 66 65 73 73 6f 72 6c 61 73 74 54 66 6f 72 65 69 67 6e 6d 61 6a 6f 72 } //1 professorlastTforeignmajor
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}