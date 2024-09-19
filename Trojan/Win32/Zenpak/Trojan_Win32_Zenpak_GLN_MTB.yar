
rule Trojan_Win32_Zenpak_GLN_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d0 42 b9 ?? ?? ?? ?? e2 ?? 29 c2 8d 05 ?? ?? ?? ?? 31 28 89 c2 01 c2 8d 05 ?? ?? ?? ?? 89 18 8d 05 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}