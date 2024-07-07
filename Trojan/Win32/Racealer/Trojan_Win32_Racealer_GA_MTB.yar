
rule Trojan_Win32_Racealer_GA_MTB{
	meta:
		description = "Trojan:Win32/Racealer.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 6a 00 ff 15 90 01 04 ff 15 90 01 04 8b 0d 90 01 04 0f b6 91 90 01 04 03 15 90 01 04 89 15 90 01 04 a1 90 01 04 33 d2 b9 00 01 00 00 f7 f1 89 15 90 01 04 81 3d 90 01 04 21 06 00 00 75 90 00 } //1
		$a_02_1 = {0f b6 d0 33 da 8b 45 90 01 01 03 45 90 01 01 88 18 8b 4d 90 01 01 83 e9 01 89 4d 90 01 01 eb 90 01 01 5b 8b e5 5d c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}