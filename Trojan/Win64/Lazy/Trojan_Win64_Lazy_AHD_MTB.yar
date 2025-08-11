
rule Trojan_Win64_Lazy_AHD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 08 8b 4d 03 89 48 04 0f b6 4d 07 88 48 08 0f b6 4d 08 88 48 09 48 8d 78 10 48 89 7d ef 48 89 77 38 48 8b 4d 47 48 85 c9 74 ?? 48 8b 01 48 8b d7 ff 10 } //3
		$a_03_1 = {48 8d 40 01 80 3c 03 00 75 ?? 4c 8d 48 01 48 c7 44 24 20 00 00 00 00 4c 8b c3 49 8b d6 48 8b cf ff 15 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}