
rule Trojan_Win32_Lazy_GVB_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bf 60 01 00 00 99 f7 ff 8b bd ?? ?? ?? ?? 8a 04 3a 8b bd ?? ?? ?? ?? 30 04 39 41 3b ce } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}