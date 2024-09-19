
rule Trojan_Win32_GCleaner_GNX_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.GNX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 14 38 83 fe ?? ?? ?? 8b 85 ?? ?? ?? ?? 6a 00 50 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}