
rule Trojan_Win32_Zenpak_V_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 01 d0 4a 4a 01 1d ?? ?? ?? ?? 31 d0 ba ?? ?? ?? ?? 83 ea ?? 8d 05 ?? ?? ?? ?? 31 28 b9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}