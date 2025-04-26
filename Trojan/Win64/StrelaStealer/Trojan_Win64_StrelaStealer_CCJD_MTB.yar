
rule Trojan_Win64_StrelaStealer_CCJD_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.CCJD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 03 00 00 0f b6 ?? ?? 04 32 ?? ?? 04 04 00 00 80 ?? 0c 88 ?? ?? 04 04 00 00 48 83 ?? 01 84 ?? 75 } //4
		$a_01_1 = {65 6e 74 72 79 } //1 entry
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}