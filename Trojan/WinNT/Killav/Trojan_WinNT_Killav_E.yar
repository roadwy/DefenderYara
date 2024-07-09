
rule Trojan_WinNT_Killav_E{
	meta:
		description = "Trojan:WinNT/Killav.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 } //1
		$a_02_1 = {14 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 08 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 0c 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 10 20 22 00 0f 84 } //1
		$a_02_2 = {20 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 24 20 22 00 0f 84 ?? ?? ?? ?? 81 7d ?? 57 e1 22 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}