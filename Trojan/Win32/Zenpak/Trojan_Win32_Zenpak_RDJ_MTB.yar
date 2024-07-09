
rule Trojan_Win32_Zenpak_RDJ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.RDJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 29 d0 4a 8d 05 ?? ?? ?? ?? 89 28 42 01 35 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}