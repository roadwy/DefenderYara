
rule Trojan_Win32_GCleaner_AGN_MTB{
	meta:
		description = "Trojan:Win32/GCleaner.AGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 80 b0 a0 bb 42 00 2e 40 83 f8 0f 72 f3 b9 a0 bb 42 00 } //1
		$a_01_1 = {8b ec 83 ec 08 a1 18 a0 42 00 33 c5 89 45 fc 64 a1 2c 00 00 00 c7 45 f8 5a 59 41 2e 8b 08 a1 78 bc 42 00 3b 81 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_GCleaner_AGN_MTB_2{
	meta:
		description = "Trojan:Win32/GCleaner.AGN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f 28 0d d0 5b 43 00 66 0f ef c8 0f 11 0d 20 ac 43 00 0f 1f 80 00 00 00 00 80 b0 20 ac 43 00 2e 40 83 f8 12 } //2
		$a_01_1 = {0f 10 05 04 ac 43 00 b8 10 00 00 00 0f 28 0d d0 5b 43 00 66 0f ef c8 0f 11 0d 04 ac 43 00 80 b0 04 ac 43 00 2e 40 83 f8 1a } //2
		$a_01_2 = {2f 66 20 26 20 65 72 61 73 65 } //1 /f & erase
		$a_01_3 = {2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 69 6d } //1 /c taskkill /im
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=6
 
}