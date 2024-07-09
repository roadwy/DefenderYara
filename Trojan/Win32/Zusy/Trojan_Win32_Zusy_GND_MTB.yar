
rule Trojan_Win32_Zusy_GND_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_03_0 = {9c 2d 45 00 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 02 2e 45 00 c7 05 ?? ?? ?? ?? 42 2d 45 00 c7 05 ?? ?? ?? ?? ea 2d 45 00 } //10
		$a_03_1 = {fc 29 45 00 a3 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 62 2a 45 00 c7 05 ?? ?? ?? ?? a2 29 45 00 c7 05 ?? ?? ?? ?? 4a 2a 45 00 } //10
		$a_01_2 = {76 6f 69 70 63 61 6c 6c 2e 74 61 6f 62 61 6f } //1 voipcall.taobao
		$a_01_3 = {71 73 79 6f 75 2e 63 6f 6d } //1 qsyou.com
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=12
 
}