
rule Trojan_Win32_Zusy_MBHZ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MBHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {64 61 74 75 6f 72 6c 70 2e 64 6c 6c } //1 datuorlp.dll
		$a_01_1 = {74 79 6b 6e 69 61 } //1 tyknia
		$a_01_2 = {77 6a 72 69 71 70 6c 6d } //1 wjriqplm
		$a_01_3 = {78 7a 76 6a 68 71 74 } //1 xzvjhqt
		$a_01_4 = {7a 6b 64 79 70 6a 68 6c } //1 zkdypjhl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}