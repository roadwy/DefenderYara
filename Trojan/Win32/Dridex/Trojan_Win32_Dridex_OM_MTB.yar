
rule Trojan_Win32_Dridex_OM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.OM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 08 8b e5 5d c3 90 09 21 00 33 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 01 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d } //1
		$a_02_1 = {8b 55 08 89 0a a1 [0-04] 8b [0-05] 8d [0-06] 89 [0-05] a1 [0-04] a3 [0-04] 8b [0-05] 89 [0-05] 8b [0-05] 83 [0-02] 89 [0-05] 90 18 e8 [0-04] 8b e5 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}