
rule Trojan_Win32_Bamital_N{
	meta:
		description = "Trojan:Win32/Bamital.N,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {5b 25 73 75 62 69 64 5d } //1 [%subid]
		$a_00_1 = {44 69 73 61 62 6c 65 53 52 } //1 DisableSR
		$a_03_2 = {8b 45 0c 8b 4d 08 80 38 e9 75 09 39 48 01 75 04 c9 c2 14 00 8b 55 0c 2b 55 14 52 ff 75 18 e8 ?? ?? ?? ?? 8b 4d 0c 66 8b 50 04 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}