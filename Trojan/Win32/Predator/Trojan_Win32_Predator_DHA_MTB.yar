
rule Trojan_Win32_Predator_DHA_MTB{
	meta:
		description = "Trojan:Win32/Predator.DHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f9 0c 73 18 8a 44 0d ?? 32 c2 f6 d0 88 44 0d 90 1b 00 41 89 8d ?? ?? ?? ?? 8a 55 ?? eb e3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}