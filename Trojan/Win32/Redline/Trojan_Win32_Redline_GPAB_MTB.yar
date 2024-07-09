
rule Trojan_Win32_Redline_GPAB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b cb e8 ca 36 00 00 80 86 ?? ?? ?? ?? ?? 46 81 fe 00 } //1
		$a_81_1 = {53 6f 76 69 65 74 20 61 72 69 73 74 6f 20 62 61 72 69 73 74 6f } //1 Soviet aristo baristo
		$a_81_2 = {75 53 47 79 75 54 59 41 53 74 79 41 } //1 uSGyuTYAStyA
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}