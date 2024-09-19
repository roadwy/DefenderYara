
rule Trojan_Win32_Madokwa_YAA_MTB{
	meta:
		description = "Trojan:Win32/Madokwa.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {21 d0 33 55 e6 89 4d e7 32 75 e4 0b 45 f1 89 55 eb } //1
		$a_01_1 = {8b 04 1f 33 45 f0 89 04 1e } //10
		$a_01_2 = {56 69 72 74 c7 45 90 01 01 75 61 6c 50 c7 45 90 01 01 72 6f 74 65 c7 45 90 01 01 63 74 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}