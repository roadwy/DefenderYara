
rule Trojan_Win32_OyesterLoader_WQF_MTB{
	meta:
		description = "Trojan:Win32/OyesterLoader.WQF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 10 53 6a 01 89 87 24 03 00 00 88 9f 2c 03 00 00 89 9f 30 03 00 00 89 9f 28 03 00 00 89 b7 34 03 00 00 83 4e 0c ff 53 ff 15 44 f0 08 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}