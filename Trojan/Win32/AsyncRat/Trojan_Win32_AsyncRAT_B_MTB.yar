
rule Trojan_Win32_AsyncRAT_B_MTB{
	meta:
		description = "Trojan:Win32/AsyncRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 11 32 05 ?? ?? ?? ?? 8b 4d ?? 8b 11 8b 4a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}