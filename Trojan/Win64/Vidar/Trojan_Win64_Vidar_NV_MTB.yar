
rule Trojan_Win64_Vidar_NV_MTB{
	meta:
		description = "Trojan:Win64/Vidar.NV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f 57 ff 4c 8b 35 8a c3 18 00 65 4d 8b 36 4d 8b 36 0f b6 44 24 1f 84 c0 74 12 48 8b 4c 24 20 } //2
		$a_01_1 = {48 8b 0d a6 32 15 00 65 48 8b 09 48 8b 7c 24 08 48 8b 77 08 48 2b 34 24 48 89 39 48 89 f4 89 44 24 20 5d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}