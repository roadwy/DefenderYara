
rule Trojan_Win32_Inject_LO_MTB{
	meta:
		description = "Trojan:Win32/Inject.LO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 01 41 84 c0 75 ?? 2b ca 8b c6 33 d2 f7 f1 46 8a 82 ?? ?? ?? 00 30 44 3e ff 3b f3 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}