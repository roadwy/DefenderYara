
rule Trojan_Win32_ZgRAT_A_MTB{
	meta:
		description = "Trojan:Win32/ZgRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 ad 66 83 f0 ?? 66 ab 66 83 f8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}