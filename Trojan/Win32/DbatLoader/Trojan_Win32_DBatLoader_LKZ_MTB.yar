
rule Trojan_Win32_DBatLoader_LKZ_MTB{
	meta:
		description = "Trojan:Win32/DBatLoader.LKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 04 1a 6a 0f 59 8b 45 ac 33 c9 8b 55 a8 e8 ?? ?? ?? ?? 8d 04 b6 8b 44 c7 14 03 45 b8 8b 55 ac 8b 4d a4 e8 ?? ?? ?? ?? 46 83 fe 06 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}