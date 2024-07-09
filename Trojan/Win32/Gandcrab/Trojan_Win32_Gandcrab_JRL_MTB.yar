
rule Trojan_Win32_Gandcrab_JRL_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.JRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 04 1e 46 3b f7 7c 90 0a 12 00 e8 ?? ?? ?? 00 } //1
		$a_02_1 = {00 33 c5 89 45 ?? 69 05 ?? ?? ?? 00 ?? ?? ?? ?? 05 ?? ?? ?? ?? a3 90 0a 28 00 a1 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}