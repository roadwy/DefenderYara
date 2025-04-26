
rule Trojan_Win32_Strab_GMP_MTB{
	meta:
		description = "Trojan:Win32/Strab.GMP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c0 c8 03 32 86 ?? ?? ?? ?? 88 81 ?? ?? ?? ?? 8d 46 01 99 41 f7 fb 8b f2 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}