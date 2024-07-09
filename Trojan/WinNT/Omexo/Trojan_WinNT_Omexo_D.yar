
rule Trojan_WinNT_Omexo_D{
	meta:
		description = "Trojan:WinNT/Omexo.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {74 03 8b 70 01 6a 00 89 35 ?? ?? ?? ?? 68 } //1
		$a_01_1 = {74 1a 0f b7 57 06 83 c6 01 83 c3 28 3b f2 72 e0 5f 5e 5d b8 25 02 00 c0 } //1
		$a_01_2 = {bf 03 00 00 f0 eb 05 bf 01 00 00 f0 } //1
		$a_01_3 = {17 00 ca 5a 59 5a 5a 5a } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}