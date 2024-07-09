
rule Trojan_Win32_Stealc_MBFW_MTB{
	meta:
		description = "Trojan:Win32/Stealc.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b f0 89 45 ?? 8b c6 89 75 ?? c1 e0 ?? 89 45 ?? 8b 45 } //1
		$a_03_1 = {d3 ea 03 55 ?? 89 55 ?? 33 55 ?? 33 c2 89 5d ?? 2b f8 89 45 } //1
		$a_01_2 = {01 45 ec 8b 45 ec 31 45 e8 8b 45 f4 33 45 e8 2b f0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}