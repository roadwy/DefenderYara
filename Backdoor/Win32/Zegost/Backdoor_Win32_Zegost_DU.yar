
rule Backdoor_Win32_Zegost_DU{
	meta:
		description = "Backdoor:Win32/Zegost.DU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 80 04 11 ?? 03 ca 8b 4d fc 80 34 11 ?? 03 ca 42 3b d0 7c e9 } //1
		$a_03_1 = {53 50 c6 45 ?? 48 c6 45 ?? 61 c6 45 ?? 63 c6 45 ?? 6b c6 45 ?? 65 c6 45 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}