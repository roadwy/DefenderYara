
rule Trojan_Win32_GCleaner_AMAP_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AMAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 30 08 83 fb 0f 75 ?? 57 57 57 57 ff 15 ?? ?? ?? ?? 46 3b f3 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}