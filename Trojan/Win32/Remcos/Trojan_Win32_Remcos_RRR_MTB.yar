
rule Trojan_Win32_Remcos_RRR_MTB{
	meta:
		description = "Trojan:Win32/Remcos.RRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 0c 00 00 "
		
	strings :
		$a_02_0 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_1 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_2 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_3 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_4 = {ff 34 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 01 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_5 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_6 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_7 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_8 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_9 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_10 = {8b 1c 17 3d ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
		$a_02_11 = {8b 1c 17 81 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 31 f3 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 1c 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 83 c2 04 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1+(#a_02_8  & 1)*1+(#a_02_9  & 1)*1+(#a_02_10  & 1)*1+(#a_02_11  & 1)*1) >=1
 
}