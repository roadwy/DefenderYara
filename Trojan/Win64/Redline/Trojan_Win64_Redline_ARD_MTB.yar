
rule Trojan_Win64_Redline_ARD_MTB{
	meta:
		description = "Trojan:Win64/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 54 24 10 48 89 4c 24 08 48 83 ec 38 48 8b 4c 24 40 ff 15 ?? ?? ?? ?? 48 89 44 24 28 48 8b 54 24 48 48 8b 4c 24 28 ff 15 ?? ?? ?? ?? 48 89 44 24 20 48 8b 44 24 20 48 83 c4 38 c3 } //2
		$a_03_1 = {48 8b 94 24 80 02 00 00 48 8d 4c 24 4c ff 15 ?? ?? ?? ?? 85 c0 75 43 44 8b 44 24 28 33 d2 b9 01 00 00 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}