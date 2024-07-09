
rule Trojan_Win32_Harasom_A{
	meta:
		description = "Trojan:Win32/Harasom.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 53 89 06 58 6a 4f 66 89 45 ?? 58 6a 46 66 89 45 ?? 58 6a 54 66 89 45 ?? 58 6a 57 66 89 45 } //1
		$a_03_1 = {56 33 f6 68 ?? ?? ?? ?? 46 e8 ?? ?? ?? ?? 59 6a 40 68 00 30 00 00 ff 75 0c 6a 00 ff 75 08 ff d0 5e 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}