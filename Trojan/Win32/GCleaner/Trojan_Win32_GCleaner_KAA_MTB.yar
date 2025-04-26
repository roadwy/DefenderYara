
rule Trojan_Win32_GCleaner_KAA_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 8d f8 f7 ff ff 8b 85 f4 f7 ff ff 30 0c 38 83 fb 0f } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}