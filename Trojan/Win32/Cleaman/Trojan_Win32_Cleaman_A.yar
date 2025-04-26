
rule Trojan_Win32_Cleaman_A{
	meta:
		description = "Trojan:Win32/Cleaman.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c6 03 e9 6a 04 43 53 ff d6 85 c0 75 ?? 2b ?? ?? ?? 83 ef 05 89 3b } //1
		$a_00_1 = {b9 00 50 00 00 66 39 4e 02 75 64 66 83 3e 02 75 5e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}