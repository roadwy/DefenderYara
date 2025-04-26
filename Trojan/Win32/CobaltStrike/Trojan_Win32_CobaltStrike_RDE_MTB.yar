
rule Trojan_Win32_CobaltStrike_RDE_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.RDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 fc c6 45 f0 46 c6 45 f1 69 c6 45 f2 6e c6 45 f3 64 c6 45 f4 57 c6 45 f5 69 c6 45 f6 6e c6 45 f7 64 c6 45 f8 6f c6 45 f9 77 c6 45 fa 57 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}