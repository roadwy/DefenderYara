
rule Trojan_Win64_StrelaStealer_ASK_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 34 0c 88 84 ?? 04 04 00 00 48 83 c1 01 4c 39 ?? 72 } //4
		$a_03_1 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 80 ?? 0c 42 88 ?? ?? 04 04 00 00 48 83 ?? 01 84 db 75 } //4
		$a_03_2 = {ff 03 00 00 0f b6 ?? ?? 04 32 8c 33 04 04 00 00 80 f1 0c 88 8c 33 04 04 00 00 48 83 c3 01 84 d2 75 } //4
		$a_01_3 = {65 6e 74 72 79 } //1 entry
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_03_2  & 1)*4+(#a_01_3  & 1)*1) >=5
 
}