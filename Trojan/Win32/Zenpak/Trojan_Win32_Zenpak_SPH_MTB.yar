
rule Trojan_Win32_Zenpak_SPH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.SPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 57 6a 40 68 00 30 00 00 68 1c dc 04 00 6a 00 8b f9 ff 15 ?? ?? ?? ?? 8b f0 85 f6 75 } //1
		$a_01_1 = {31 32 35 2e 31 32 34 2e 38 36 2e 33 31 } //1 125.124.86.31
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}