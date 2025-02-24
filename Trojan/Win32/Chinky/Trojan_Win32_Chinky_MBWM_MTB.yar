
rule Trojan_Win32_Chinky_MBWM_MTB{
	meta:
		description = "Trojan:Win32/Chinky.MBWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {19 40 00 02 00 b7 01 68 [0-0f] 1a 40 00 88 95 } //1
		$a_01_1 = {64 17 40 00 20 13 40 00 04 f8 30 01 00 ff ff ff 08 00 00 00 01 00 00 00 02 00 00 00 e9 00 00 00 80 12 40 00 b4 11 40 00 70 11 40 00 78 00 00 00 81 00 00 00 8a } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}