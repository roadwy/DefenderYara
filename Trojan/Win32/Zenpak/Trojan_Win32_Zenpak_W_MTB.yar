
rule Trojan_Win32_Zenpak_W_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 8d 05 ?? ?? ?? ?? 01 38 01 c2 83 ea ?? 8d 05 ?? ?? ?? ?? 01 28 83 c2 ?? 48 83 c0 05 31 35 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}