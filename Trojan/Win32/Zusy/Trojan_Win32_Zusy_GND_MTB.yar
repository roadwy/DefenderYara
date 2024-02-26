
rule Trojan_Win32_Zusy_GND_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_03_0 = {9c 2d 45 00 a3 90 01 04 c7 05 90 01 04 02 2e 45 00 c7 05 90 01 04 42 2d 45 00 c7 05 90 01 04 ea 2d 45 00 90 00 } //0a 00 
		$a_03_1 = {fc 29 45 00 a3 90 01 04 c7 05 90 01 04 62 2a 45 00 c7 05 90 01 04 a2 29 45 00 c7 05 90 01 04 4a 2a 45 00 90 00 } //01 00 
		$a_01_2 = {76 6f 69 70 63 61 6c 6c 2e 74 61 6f 62 61 6f } //01 00  voipcall.taobao
		$a_01_3 = {71 73 79 6f 75 2e 63 6f 6d } //00 00  qsyou.com
	condition:
		any of ($a_*)
 
}