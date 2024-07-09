
rule Trojan_Win32_Chadivendo_STC{
	meta:
		description = "Trojan:Win32/Chadivendo.STC,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 68 [0-10] ff 15 ?? e0 00 10 ff 15 ?? e0 00 10 68 ?? ?? ?? 10 ff 15 ?? e0 00 10 } //1
		$a_02_1 = {43 72 65 61 74 65 50 72 6f 63 65 73 73 41 [0-10] 44 65 62 75 67 42 72 65 61 6b } //1
		$a_02_2 = {5c 54 65 6d 70 5c 65 64 67 ?? ?? ?? ?? 2e 74 6d 70 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}