
rule Trojan_Win32_Ekstak_GZM_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 44 24 08 50 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 6a 01 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 6a 14 6a 40 ff 15 ?? ?? ?? ?? 8b f8 6a 01 57 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}