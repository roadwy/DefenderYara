
rule Trojan_BAT_Ursu_AUR_MTB{
	meta:
		description = "Trojan:BAT/Ursu.AUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 13 07 11 09 11 07 1f 2a 61 d1 13 07 fe 0d 07 00 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Ursu_AUR_MTB_2{
	meta:
		description = "Trojan:BAT/Ursu.AUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {17 59 0c 17 0d 2b 2d 17 13 04 2b 1f 02 11 04 09 6f ?? ?? ?? 0a 13 05 06 12 05 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 11 04 17 58 13 04 11 04 07 31 dc } //2
		$a_01_1 = {74 00 65 00 73 00 74 00 53 00 74 00 2e 00 65 00 78 00 65 00 } //1 testSt.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_BAT_Ursu_AUR_MTB_3{
	meta:
		description = "Trojan:BAT/Ursu.AUR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 06 16 72 1b 00 00 70 a2 06 17 28 ?? 00 00 06 a2 06 18 72 5f 00 00 70 a2 06 19 28 ?? 00 00 06 a2 06 1a 72 77 00 00 70 a2 06 1b 28 ?? 00 00 06 a2 06 1c 72 83 00 00 70 a2 06 1d 28 } //1
		$a_01_1 = {0b 07 16 72 fb 00 00 70 a2 07 17 7e 01 00 00 04 a2 07 18 72 35 01 00 70 a2 07 19 7e 02 00 00 04 a2 07 1a 72 61 01 00 70 a2 07 1b 02 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}