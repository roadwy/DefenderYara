
rule Trojan_Win32_Predator_J_MTB{
	meta:
		description = "Trojan:Win32/Predator.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f6 d1 32 8c 14 ?? ?? ?? ?? 88 8c 14 ?? ?? ?? ?? 42 3b d7 73 09 8a 8c 24 ?? ?? ?? ?? eb e2 } //1
		$a_01_1 = {55 8b ec 8a 01 f6 d0 32 45 08 5d c2 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}