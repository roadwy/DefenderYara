
rule Trojan_Win64_Tedy_SXI_MTB{
	meta:
		description = "Trojan:Win64/Tedy.SXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 04 24 48 ff c0 48 89 04 24 48 83 3c 24 42 73 ?? 48 8b 04 24 48 8b 0d ?? ?? ?? ?? 48 03 c8 48 8b c1 0f be 00 83 f0 34 48 8b 0c 24 48 8b 54 24 ?? 48 03 d1 48 8b ca 88 01 eb } //30
		$a_03_1 = {48 33 c4 48 89 84 24 ?? ?? ?? ?? 48 8d 84 24 ?? ?? ?? ?? 48 8b f8 33 c0 b9 43 00 00 00 f3 aa 48 8d 8c 24 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}