
rule Trojan_Win32_Vidar_AMAJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 d8 8b 45 d8 31 18 83 45 ec 04 6a 00 e8 ?? ?? ?? ?? 83 45 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_AMAJ_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 8b c8 8b 45 ?? 33 d2 f7 f1 8b 45 ?? 0f be 04 10 33 d8 8b 45 ?? 03 45 ?? 88 18 } //2
		$a_03_1 = {6a 14 ff 15 ?? ?? ?? ?? 6a 14 ff 15 ?? ?? ?? ?? 6a 14 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}