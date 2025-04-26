
rule Trojan_Win32_XMRig_B_MTB{
	meta:
		description = "Trojan:Win32/XMRig.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 89 45 ?? 8b c6 d3 e8 03 45 ?? 89 45 f4 8b 45 ?? 31 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}