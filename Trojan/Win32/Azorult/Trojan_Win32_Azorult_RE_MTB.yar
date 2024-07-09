
rule Trojan_Win32_Azorult_RE_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ec 83 e4 f8 b8 78 41 00 00 e8 ?? ?? ?? ?? 81 3d ?? ?? ?? ?? 77 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}