
rule Trojan_Win32_Lazy_CAF_MTB{
	meta:
		description = "Trojan:Win32/Lazy.CAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 5d e4 8a 44 1d 10 88 44 3d 10 88 4c 1d 10 0f b6 44 3d 10 03 c2 0f b6 c0 83 65 fc ?? 8a 44 05 10 32 86 ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 83 4d fc ff eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}