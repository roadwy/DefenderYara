
rule Trojan_Win32_Injector_BK_bit{
	meta:
		description = "Trojan:Win32/Injector.BK!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 fb 8b 7c ?? ?? 31 fb 33 5c ?? ?? 8b 7c ?? ?? 31 fb 89 5c ?? ?? 68 01 00 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}