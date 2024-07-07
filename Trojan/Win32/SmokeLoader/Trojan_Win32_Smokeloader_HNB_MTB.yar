
rule Trojan_Win32_Smokeloader_HNB_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {f7 65 f4 8b 45 f4 } //1
		$a_01_1 = {c7 45 fc 20 00 00 00 83 45 fc 20 8d 45 f8 50 ff 75 fc } //1
		$a_01_2 = {83 65 fc 00 81 45 fc 00 00 00 00 8b 45 fc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}