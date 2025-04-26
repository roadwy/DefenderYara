
rule Trojan_Win32_Zenpak_U_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e8 50 8f 05 ?? ?? ?? ?? 48 42 83 f2 ?? 8d 05 ?? ?? ?? ?? 89 18 8d 05 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}