
rule Trojan_Win32_Havokiz_SC{
	meta:
		description = "Trojan:Win32/Havokiz.SC,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 48 89 e6 48 83 e4 f0 48 83 ec 20 e8 0f 00 00 00 48 89 f4 5e c3 } //1
		$a_01_1 = {65 48 8b 04 25 60 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}