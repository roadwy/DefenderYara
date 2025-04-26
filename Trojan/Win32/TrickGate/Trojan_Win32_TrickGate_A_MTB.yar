
rule Trojan_Win32_TrickGate_A_MTB{
	meta:
		description = "Trojan:Win32/TrickGate.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 c8 0f b6 4d ?? 31 c8 88 c2 8b 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}