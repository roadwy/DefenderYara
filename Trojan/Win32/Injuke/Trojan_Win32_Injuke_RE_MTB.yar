
rule Trojan_Win32_Injuke_RE_MTB{
	meta:
		description = "Trojan:Win32/Injuke.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 8b 11 81 f2 ?? ?? ?? ?? 89 11 83 c0 04 3b f0 77 ed [0-30] 50 6a 40 8b 45 f4 50 8b 45 fc 50 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}