
rule Trojan_Win32_Ekstak_DSK_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_02_0 = {29 f8 5f 57 bf ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 81 f7 ?? ?? ?? ?? 29 f8 5f 31 c3 } //2
		$a_02_1 = {31 d8 5b 51 b9 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 f1 ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? e9 } //2
		$a_02_2 = {29 c7 58 53 bb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 81 eb ?? ?? ?? ?? 31 df 5b 50 } //2
		$a_02_3 = {01 d9 5b 50 b8 ?? ?? ?? ?? 81 f0 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 81 f0 ?? ?? ?? ?? 31 c1 58 52 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2+(#a_02_2  & 1)*2+(#a_02_3  & 1)*2) >=2
 
}