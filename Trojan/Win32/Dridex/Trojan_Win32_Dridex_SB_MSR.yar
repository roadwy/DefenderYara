
rule Trojan_Win32_Dridex_SB_MSR{
	meta:
		description = "Trojan:Win32/Dridex.SB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6a 6f 72 64 61 6e } //1 jordan
		$a_01_1 = {62 75 6c 6c 73 68 69 74 } //1 bullshit
		$a_01_2 = {61 73 73 68 6f 6c 65 } //1 asshole
		$a_01_3 = {63 6f 77 62 6f 79 } //1 cowboy
		$a_01_4 = {66 61 75 6c 74 65 64 } //1 faulted
		$a_01_5 = {54 77 69 74 74 65 72 } //1 Twitter
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}