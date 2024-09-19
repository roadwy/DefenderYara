
rule Trojan_Win64_StrelaStealer_DB_MTB{
	meta:
		description = "Trojan:Win64/StrelaStealer.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,33 00 33 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff 03 00 00 0f b6 ?? ?? 04 32 84 ?? ?? 04 00 00 34 0c 88 84 ?? ?? 04 00 00 48 83 ?? 01 4c 39 ?? 72 90 09 03 00 89 ?? 25 } //50
		$a_03_1 = {ff 03 00 00 [0-01] 0f b6 ?? ?? 04 30 14 08 48 83 c1 01 4c 39 ?? 72 90 09 04 00 89 ?? 81 } //50
		$a_01_2 = {65 6e 74 72 79 } //1 entry
	condition:
		((#a_03_0  & 1)*50+(#a_03_1  & 1)*50+(#a_01_2  & 1)*1) >=51
 
}