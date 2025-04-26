
rule Trojan_Win64_StrelaStealer_CCJC_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.CCJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 80 f1 0c 88 8c 2b 04 04 00 00 48 83 c3 01 84 d2 75 d5 } //4
		$a_03_1 = {ff 03 00 00 42 0f b6 ?? ?? 04 42 32 ?? ?? 04 04 00 00 80 ?? 0c 42 88 ?? ?? 04 04 00 00 48 83 c3 01 [0-03] 75 } //4
		$a_01_2 = {65 6e 74 72 79 } //1 entry
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*4+(#a_01_2  & 1)*1) >=5
 
}