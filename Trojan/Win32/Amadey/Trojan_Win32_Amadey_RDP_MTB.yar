
rule Trojan_Win32_Amadey_RDP_MTB{
	meta:
		description = "Trojan:Win32/Amadey.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 01 00 00 00 c1 e0 00 c6 80 ?? ?? ?? ?? 65 b9 01 00 00 00 6b d1 09 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}