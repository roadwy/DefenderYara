
rule Trojan_Win32_GCleaner_MFT_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.MFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 83 65 fc 00 8d 75 fc e8 ?? ?? ?? ?? 8b 45 08 8a 4d fc 30 0c 38 47 3b fb 7c } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}