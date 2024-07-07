
rule Trojan_Win32_Zenpak_V_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 01 d0 4a 4a 01 1d 90 01 04 31 d0 ba 90 01 04 83 ea 90 01 01 8d 05 90 01 04 31 28 b9 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}