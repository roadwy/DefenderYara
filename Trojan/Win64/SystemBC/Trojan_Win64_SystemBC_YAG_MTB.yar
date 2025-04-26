
rule Trojan_Win64_SystemBC_YAG_MTB{
	meta:
		description = "Trojan:Win64/SystemBC.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 48 8b f4 48 83 e4 f0 48 83 ec 20 e8 ?? ?? ?? ?? 48 8b e6 5e } //1
		$a_01_1 = {c7 45 18 63 6c 6f 73 c7 45 1c 65 73 6f 63 c7 45 20 6b 65 74 00 c7 45 b8 73 68 75 74 c7 45 bc 64 6f 77 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}