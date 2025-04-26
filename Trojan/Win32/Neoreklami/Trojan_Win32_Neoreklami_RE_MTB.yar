
rule Trojan_Win32_Neoreklami_RE_MTB{
	meta:
		description = "Trojan:Win32/Neoreklami.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {99 89 84 24 ?? ?? 00 00 89 94 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00 90 09 09 00 00 00 33 84 24 ?? ?? 00 00 } //1
		$a_03_1 = {d3 f8 99 89 84 24 ?? ?? 00 00 89 94 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00 ff b4 24 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}