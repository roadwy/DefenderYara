
rule Trojan_Win32_Neoreblamy_NTC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 7d 83 65 d4 00 eb 07 8b 45 d4 40 89 45 d4 81 7d d4 } //1
		$a_03_1 = {33 d2 3b c8 8b 85 ?? ?? ff ff 0f 9e c2 33 c9 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}