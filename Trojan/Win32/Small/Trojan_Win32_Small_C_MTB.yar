
rule Trojan_Win32_Small_C_MTB{
	meta:
		description = "Trojan:Win32/Small.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {c3 55 89 e5 90 90 c9 68 ?? ?? ?? ?? c3 80 74 0a ff 20 e2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}