
rule Trojan_Win32_Alureon_FK{
	meta:
		description = "Trojan:Win32/Alureon.FK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 45 f0 e9 ab 56 e8 } //1
		$a_01_1 = {3c 0d 75 04 c6 07 00 47 80 3f 0a } //1
		$a_03_2 = {74 70 80 3f 2f be ?? ?? ?? ?? 6a 01 75 0f } //1
		$a_01_3 = {50 75 72 70 6c 65 48 61 7a 65 } //1 PurpleHaze
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}