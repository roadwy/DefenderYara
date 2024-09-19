
rule Trojan_Win32_GCleaner_MFC_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.MFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 83 a5 f8 f7 ff ff 00 8d b5 f8 f7 ff ff e8 ?? ?? ?? ?? 8a 85 f8 f7 ff ff 30 04 3b 83 7d 08 0f 75 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}