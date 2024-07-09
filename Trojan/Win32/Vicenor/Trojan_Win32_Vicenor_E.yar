
rule Trojan_Win32_Vicenor_E{
	meta:
		description = "Trojan:Win32/Vicenor.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 30 00 00 ff 77 50 ff 77 34 ff b5 ?? ?? ff ff e8 ?? ?? ?? ?? 89 85 ?? ?? ff ff 6a 00 ff 77 54 ff 75 ?? ff b5 ?? ?? ff ff ff b5 ?? ?? ff ff e8 } //2
		$a_01_1 = {31 00 44 00 46 00 41 00 47 00 58 00 00 00 } //1
		$a_03_2 = {2d 00 6f 00 20 00 68 00 74 00 74 00 70 00 [0-02] 3a 00 2f 00 2f 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}