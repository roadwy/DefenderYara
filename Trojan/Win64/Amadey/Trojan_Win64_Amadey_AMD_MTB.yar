
rule Trojan_Win64_Amadey_AMD_MTB{
	meta:
		description = "Trojan:Win64/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 f7 e9 48 01 ca 48 d1 fa 48 89 cb 48 c1 f9 3f 48 29 ca 48 85 d2 0f 8e a4 00 00 00 48 8b 44 24 68 48 89 d1 48 89 c6 48 } //2
		$a_01_1 = {48 89 44 24 18 48 8b 10 48 8d 59 ff 48 89 1c 24 48 8b 1a ff d3 48 8b 44 24 08 48 89 44 24 10 48 8b 4c 24 18 48 8b 11 48 8b 4c 24 30 48 83 c1 fe } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}
rule Trojan_Win64_Amadey_AMD_MTB_2{
	meta:
		description = "Trojan:Win64/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 5c 24 38 41 b8 50 00 00 00 89 5c 24 30 45 33 c9 c7 44 24 28 03 00 00 00 49 8b ce 48 89 5c 24 20 ff 15 ?? ?? ?? ?? 48 8b f0 48 8b 44 24 48 4c 8b c0 48 83 78 18 10 72 03 4c 8b 00 48 89 5c 24 38 48 8d 15 76 c0 08 00 89 5c 24 30 45 33 c9 48 89 5c 24 28 48 8b ce 48 89 5c 24 20 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Amadey_AMD_MTB_3{
	meta:
		description = "Trojan:Win64/Amadey.AMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 15 c1 7d 07 00 48 8b c8 ff 15 ?? ?? ?? ?? 48 8d 15 c1 7d 07 00 48 8b cf 48 89 05 67 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 c2 7d 07 00 48 8b cf 48 89 05 58 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 c3 7d 07 00 48 8b cf 48 89 05 49 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 bc 7d 07 00 48 8b cf 48 89 05 3a 8a 07 00 ff 15 ?? ?? ?? ?? 48 8d 15 bd 7d 07 00 48 8b cf } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}