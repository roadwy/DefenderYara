
rule Trojan_Win32_Sefnit_E{
	meta:
		description = "Trojan:Win32/Sefnit.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 b7 a3 42 17 [6a e9 eb] } //1
		$a_03_1 = {01 40 00 80 90 09 03 00 c7 45 } //1
		$a_03_2 = {55 83 2c 24 ?? 90 18 6a ?? 90 18 68 ?? ?? ?? ?? 90 18 e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}