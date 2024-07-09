
rule Trojan_Win32_Tamgitel_A{
	meta:
		description = "Trojan:Win32/Tamgitel.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c9 66 b9 [0-05] 80 34 11 04 [0-05] e2 } //1
		$a_01_1 = {c7 60 a5 34 04 04 04 81 c4 7c } //1
		$a_03_2 = {57 37 df 52 c2 41 ?? 45 c2 41 ?? 67 c2 41 ?? 68 c2 41 ?? 51 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}