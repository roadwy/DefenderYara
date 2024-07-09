
rule Trojan_Win32_Hancitor_MTB{
	meta:
		description = "Trojan:Win32/Hancitor!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {ff d0 0f 81 90 0a 50 00 6a 40 eb [0-30] 8b 00 eb 90 0a ff 00 b9 00 00 00 00 eb [0-50] b8 ?? ?? ?? ?? 71 [0-50] 30 07 e9 [0-a0] 47 e9 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}