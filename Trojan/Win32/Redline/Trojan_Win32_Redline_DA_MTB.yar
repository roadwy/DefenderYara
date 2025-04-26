
rule Trojan_Win32_Redline_DA_MTB{
	meta:
		description = "Trojan:Win32/Redline.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 80 04 1f } //1
		$a_01_1 = {83 c4 04 80 34 1f } //1
		$a_03_2 = {83 c4 04 80 34 1f ?? 43 39 de 0f 85 } //1
		$a_01_3 = {78 62 79 75 69 64 67 41 59 55 37 75 69 6b 6a } //1 xbyuidgAYU7uikj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_Redline_DA_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 0c 8b 45 d8 01 45 0c ff 75 f4 8d 45 f0 50 e8 ?? ?? ?? ?? 8b 45 0c 31 45 f0 8b 45 f0 29 45 f8 83 65 fc 00 8b 45 d4 01 45 fc 2b 55 fc ff 4d e8 8b 45 f8 89 55 ec 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}