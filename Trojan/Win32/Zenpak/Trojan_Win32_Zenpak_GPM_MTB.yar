
rule Trojan_Win32_Zenpak_GPM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c2 83 c0 07 40 83 f2 01 01 35 ?? ?? ?? ?? 31 d0 01 2d } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}