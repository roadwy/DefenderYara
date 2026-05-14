
rule Trojan_Win32_GCleaner_KLZ_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.KLZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f8 6a 00 e8 ?? ?? ?? ?? 03 f8 03 df 6a 00 e8 ?? ?? ?? ?? bf 04 00 00 00 2b f8 6a 00 e8 ?? ?? ?? ?? 03 f8 01 fe 3b 5d d0 0f 82 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}