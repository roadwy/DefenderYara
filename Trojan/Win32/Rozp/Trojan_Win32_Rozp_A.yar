
rule Trojan_Win32_Rozp_A{
	meta:
		description = "Trojan:Win32/Rozp.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 70 64 67 2e 64 6c 6c } //1 spdg.dll
		$a_03_1 = {8b f9 03 7d 08 8a 07 04 ?? 88 07 41 3b 4d 0c 73 02 eb ed c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}