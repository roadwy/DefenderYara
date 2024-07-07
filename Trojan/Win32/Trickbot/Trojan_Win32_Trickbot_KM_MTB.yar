
rule Trojan_Win32_Trickbot_KM_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {f6 d2 f6 d1 0a d1 22 d3 83 c4 0c 88 10 40 ff 4d 90 01 01 89 45 90 01 01 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Trickbot_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b fb 7e 90 01 01 8b 54 24 90 01 01 8d 4c 3a 90 01 01 8a 11 88 90 01 05 40 49 3b c7 7c 90 01 01 8d 47 90 01 01 83 f8 3e 88 9f 90 01 04 7d 90 00 } //1
		$a_00_1 = {45 53 45 54 20 68 79 75 6e 79 61 } //1 ESET hyunya
		$a_00_2 = {66 43 30 29 47 76 54 57 53 6a 6d 2a 79 45 42 } //1 fC0)GvTWSjm*yEB
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}