
rule Trojan_Win32_Androm_E_MTB{
	meta:
		description = "Trojan:Win32/Androm.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {6a 00 e8 6a cc f9 ff 4b 75 f6 bb [0-06] 6a 00 e8 5b cc f9 ff 4b 75 f6 6a 00 } //1
		$a_00_1 = {55 8b ec 90 90 8b 45 08 8a 10 80 f2 7b 88 10 5d c2 } //1
		$a_02_2 = {8b 06 03 c3 73 05 e8 [0-06] 50 ff 15 [0-06] 90 90 ff 06 81 3e [0-06] 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}