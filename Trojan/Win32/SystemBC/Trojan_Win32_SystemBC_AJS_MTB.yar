
rule Trojan_Win32_SystemBC_AJS_MTB{
	meta:
		description = "Trojan:Win32/SystemBC.AJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 7d e4 0f 8d 4d d0 8b c2 0f 47 4d d0 83 e0 0f 8a 80 b8 5a 68 00 32 04 11 88 04 3a 42 8b 4d e0 3b d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}