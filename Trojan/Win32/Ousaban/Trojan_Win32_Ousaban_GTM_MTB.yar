
rule Trojan_Win32_Ousaban_GTM_MTB{
	meta:
		description = "Trojan:Win32/Ousaban.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 32 4d 00 00 00 00 02 00 00 00 8b ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? 53 56 57 33 d2 89 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 45 ?? 8b 45 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}