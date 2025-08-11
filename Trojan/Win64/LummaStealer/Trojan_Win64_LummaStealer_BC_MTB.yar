
rule Trojan_Win64_LummaStealer_BC_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.BC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 18 31 c1 69 c1 95 e9 d1 5b 69 4c 24 68 95 e9 d1 5b 31 c1 89 4c 24 5c 8b 44 24 6c 83 c0 01 89 44 24 } //3
		$a_01_1 = {4c 8b 02 8b 4a 08 4c 89 00 89 48 08 c3 } //1
		$a_03_2 = {4a 0f be 84 09 ?? ?? ?? ?? 42 8a 8c 09 ?? ?? ?? ?? 48 2b d0 8b 42 fc d3 e8 41 89 40 20 48 8d 42 04 49 89 50 08 8b 0a 41 89 48 24 8b 4c 24 60 ff c1 } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=5
 
}