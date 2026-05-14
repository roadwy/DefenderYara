
rule Trojan_Win64_Vidar_ABVM_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ABVM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f af c6 83 e0 ?? ?? ?? 42 8a 04 0a 44 30 c0 42 88 04 09 8b 35 9c 26 0a 00 8b 05 9a 26 0a 00 83 f8 ?? ?? ?? 44 8d 5e 01 44 0f af de 41 83 e3 ?? ?? ?? 42 8a 04 0a 44 30 c0 42 88 04 09 ?? ?? 49 ff c1 4d 39 d1 } //5
		$a_03_1 = {8a 14 02 80 f2 ?? 88 14 08 48 ff c0 48 83 f8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}