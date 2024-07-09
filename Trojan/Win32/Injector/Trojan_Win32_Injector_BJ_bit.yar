
rule Trojan_Win32_Injector_BJ_bit{
	meta:
		description = "Trojan:Win32/Injector.BJ!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 ca 83 f1 ?? 8b ?? ?? 6b c0 ?? 99 be } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}