
rule Trojan_Win32_GCleaner_SHV_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.SHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {eb 08 0f 0a 42 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}