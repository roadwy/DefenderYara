
rule Trojan_Win32_HijackLoader_MCD_MTB{
	meta:
		description = "Trojan:Win32/HijackLoader.MCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {88 11 8d 49 ?? 8a 14 08 46 3a d3 75 } //2
		$a_01_1 = {8a 16 8b f9 8b e9 32 10 40 88 16 83 ef 01 75 f6 } //2
		$a_01_2 = {63 68 65 63 6b 69 6e 3a } //1 checkin:
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}