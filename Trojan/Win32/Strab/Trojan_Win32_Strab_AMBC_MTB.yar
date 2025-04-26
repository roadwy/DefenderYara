
rule Trojan_Win32_Strab_AMBC_MTB{
	meta:
		description = "Trojan:Win32/Strab.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b ff 8a 81 ?? ?? ?? ?? c0 c8 03 32 86 ?? ?? ?? ?? 41 88 81 ?? ?? ?? ?? 8d 46 01 99 f7 fb 8b f2 81 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}