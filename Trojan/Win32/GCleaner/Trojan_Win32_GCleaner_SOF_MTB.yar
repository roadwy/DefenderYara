
rule Trojan_Win32_GCleaner_SOF_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.SOF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 fa 03 fb 03 f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 2b f8 6a 00 e8 ?? ?? ?? ?? 03 7d a4 81 ef 5c 11 00 00 2b f8 31 3e 83 c3 04 83 c6 04 3b 5d d0 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}