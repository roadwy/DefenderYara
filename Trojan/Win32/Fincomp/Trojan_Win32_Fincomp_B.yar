
rule Trojan_Win32_Fincomp_B{
	meta:
		description = "Trojan:Win32/Fincomp.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 63 20 6e 65 74 20 73 74 6f 70 20 54 65 72 6d 53 65 72 76 69 63 65 00 } //01 00  振渠瑥猠潴⁰敔浲敓癲捩e
		$a_01_1 = {4d 79 50 69 6e 7c } //01 00  MyPin|
		$a_01_2 = {25 00 73 00 5c 00 69 00 6e 00 2e 00 74 00 65 00 6d 00 70 00 } //00 00  %s\in.temp
	condition:
		any of ($a_*)
 
}