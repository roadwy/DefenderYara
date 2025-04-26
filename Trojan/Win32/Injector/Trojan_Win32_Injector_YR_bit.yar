
rule Trojan_Win32_Injector_YR_bit{
	meta:
		description = "Trojan:Win32/Injector.YR!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {64 66 73 55 55 31 } //1 dfsUU1
		$a_03_1 = {8b 5c 24 10 33 5c 24 14 33 5c 24 ?? 33 5c 24 0c 8b 7c 24 04 [0-10] 6b ff [0-20] 31 fb 89 5c 24 10 } //1
		$a_03_2 = {8b 5c 24 0c 83 c3 ?? 89 5c 24 0c 8b 5c 24 0c 8b 7c 24 ?? 83 c7 fe 39 fb 0f 8e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}