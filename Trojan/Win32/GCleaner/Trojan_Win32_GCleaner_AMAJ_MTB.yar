
rule Trojan_Win32_GCleaner_AMAJ_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AMAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 85 d8 f7 ff ff 30 14 38 83 fb 0f 75 ?? 8d 85 ?? ?? ff ff 50 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? ?? ?? 47 3b fb 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}