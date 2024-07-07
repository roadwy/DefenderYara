
rule Trojan_Win32_Ursnif_P_MSR{
	meta:
		description = "Trojan:Win32/Ursnif.P!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 6c 1e 00 00 68 c3 33 01 00 68 1b 23 00 00 68 d8 5a 00 00 6a 00 6a 64 e8 } //1
		$a_01_1 = {c6 45 a7 00 03 c9 2b c9 0b c9 03 c0 8b 7d d0 ff d7 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}