
rule Trojan_Win32_Simda_R{
	meta:
		description = "Trojan:Win32/Simda.R,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 50 01 32 10 41 66 0f b6 c2 66 89 } //1
		$a_01_1 = {8b 4c 24 08 c6 40 18 f3 89 48 20 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}