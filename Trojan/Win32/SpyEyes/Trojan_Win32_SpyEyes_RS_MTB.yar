
rule Trojan_Win32_SpyEyes_RS_MTB{
	meta:
		description = "Trojan:Win32/SpyEyes.RS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c4 89 84 24 ?? ?? ?? ?? 81 fb 20 05 00 00 75 ?? c7 05 ?? ?? ?? ?? f6 51 9d a0 56 33 f6 3b de 7e ?? e8 ?? ?? ?? ?? 30 04 37 46 3b f3 7c } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}