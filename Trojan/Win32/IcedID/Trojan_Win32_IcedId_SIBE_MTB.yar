
rule Trojan_Win32_IcedId_SIBE_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 37 81 fd ?? ?? ?? ?? 90 18 [0-55] 8b 35 ?? ?? ?? ?? [0-05] 8d bc 2e ?? ?? ?? ?? 8b 37 [0-0a] 81 c6 ?? ?? ?? ?? [0-05] 83 c5 04 [0-10] 89 37 } //1
		$a_02_1 = {8b 45 08 89 45 ?? [0-f0] 8b 75 90 1b 00 [0-0a] ff e6 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}