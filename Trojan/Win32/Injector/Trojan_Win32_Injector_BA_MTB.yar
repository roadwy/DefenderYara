
rule Trojan_Win32_Injector_BA_MTB{
	meta:
		description = "Trojan:Win32/Injector.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f9 57 31 1f 83 c7 04 ?? ?? ?? ?? ?? 8b 3c 24 4d c0 e9 55 8b 3c 24 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}