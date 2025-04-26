
rule Trojan_Win32_GCleaner_UFF_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.UFF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 83 a5 f8 f7 ff ff 00 8d b5 f8 f7 ff ff e8 ?? ?? ?? ?? 8b 85 f4 f7 ff ff 8a 8d f8 f7 ff ff 30 0c 38 83 fb 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}