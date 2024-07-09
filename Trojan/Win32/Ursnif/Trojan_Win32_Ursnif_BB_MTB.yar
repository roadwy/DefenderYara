
rule Trojan_Win32_Ursnif_BB_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 81 c5 ?? ?? ?? ?? 0f b7 f0 89 2d ?? ?? ?? ?? 89 29 8d 6e ?? 8d 4d ?? 03 ce } //1
		$a_02_1 = {69 4c 24 20 ?? ?? ?? ?? 83 44 24 10 ?? 8d 0c 69 8b 2d ?? ?? ?? ?? 2b ce ff 4c 24 14 8b 35 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}