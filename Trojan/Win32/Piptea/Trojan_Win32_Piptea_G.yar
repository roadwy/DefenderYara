
rule Trojan_Win32_Piptea_G{
	meta:
		description = "Trojan:Win32/Piptea.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 ee 02 57 6a 00 5f 74 ?? 53 (bb ?? ?? ??|?? 68 ?? ?? ??) ?? 5b 57 68 ?? ?? ?? ?? 53 e8 ?? ?? ?? ?? 83 c4 0c 47 47 83 c3 08 } //1
		$a_01_1 = {83 c6 28 4f 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}