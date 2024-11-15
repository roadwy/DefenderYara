
rule Trojan_Win32_Zenpak_GXT_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ea 05 42 4a 40 ?? ?? 31 c2 8d 05 ?? ?? ?? ?? 01 30 e8 ?? ?? ?? ?? 4a 89 3d } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}