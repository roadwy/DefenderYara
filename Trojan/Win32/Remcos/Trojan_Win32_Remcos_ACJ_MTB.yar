
rule Trojan_Win32_Remcos_ACJ_MTB{
	meta:
		description = "Trojan:Win32/Remcos.ACJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 8b 1c 0e 90 0a ef 00 b9 ?? ?? 00 00 [0-1f] 90 90 [0-4f] 31 ff [0-1f] 90 90 [0-1f] 31 c7 } //1
		$a_03_1 = {66 09 1c 0f 90 0a 3f 00 51 59 [0-1f] 90 90 } //1
		$a_03_2 = {51 59 51 59 [0-1f] ff e0 [0-2f] 81 34 08 ?? ?? ?? ?? 90 90 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}