
rule Trojan_Win32_IcedId_SIBJ9_MTB{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ9!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4e 6f 74 69 63 65 77 65 61 74 68 65 72 5c 4f 62 73 65 72 76 65 2e 70 64 62 } //1 Noticeweather\Observe.pdb
		$a_03_1 = {89 37 83 c7 04 ff 4c 24 ?? [0-0a] 90 18 [0-40] 8b 37 [0-30] 81 c6 ?? ?? ?? ?? 89 37 83 c7 04 ff 4c 24 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_IcedId_SIBJ9_MTB_2{
	meta:
		description = "Trojan:Win32/IcedId.SIBJ9!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {54 69 65 72 61 6e 67 65 2e 70 64 62 } //1 Tierange.pdb
		$a_03_1 = {83 c2 04 83 6c 24 ?? 01 89 54 24 ?? [0-10] 90 18 [0-b0] 8b 44 24 90 1b 01 [0-10] 8b 00 [0-10] 89 44 24 ?? [0-ba] 8b 54 24 90 1b 01 [0-0a] 8b 44 24 90 1b 08 [0-0a] 05 60 34 2f 01 [0-0a] 89 02 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}