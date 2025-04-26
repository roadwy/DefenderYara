
rule Trojan_Win32_TrickBot_AE_MSR{
	meta:
		description = "Trojan:Win32/TrickBot.AE!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {51 8b 06 8b 0f 46 33 c1 88 07 47 4b 58 8b c8 75 06 } //1
		$a_02_1 = {59 ff d2 89 68 02 6a ?? 8b d0 ff d2 59 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}