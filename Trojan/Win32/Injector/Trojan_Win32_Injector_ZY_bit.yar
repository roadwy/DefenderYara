
rule Trojan_Win32_Injector_ZY_bit{
	meta:
		description = "Trojan:Win32/Injector.ZY!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c6 45 e4 4b c6 45 e5 65 c6 45 e6 72 c6 45 e7 6e c6 45 e8 65 c6 45 e9 6c c6 45 ea 33 c6 45 eb 32 c6 45 ec 2e c6 45 ed 64 c6 45 ee 6c c6 45 ef 6c } //1
		$a_03_1 = {88 19 8b 4d ?? 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 ?? 8b 45 ?? 3b 45 ?? 72 ad } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}