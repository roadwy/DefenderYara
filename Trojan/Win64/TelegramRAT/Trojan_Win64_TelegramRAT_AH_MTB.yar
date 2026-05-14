
rule Trojan_Win64_TelegramRAT_AH_MTB{
	meta:
		description = "Trojan:Win64/TelegramRAT.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 61 74 61 20 63 6f 6c 6c 65 63 74 69 6f 6e 20 63 6f 6d 70 6c 65 74 65 64 2e 20 53 65 6c 66 2d 64 65 73 74 72 75 63 74 69 6f 6e 20 69 6e 69 74 69 61 74 65 64 2e } //30 Data collection completed. Self-destruction initiated.
		$a_01_1 = {53 74 65 61 6c 65 72 20 61 63 74 69 76 61 74 65 64 20 6f 6e 3a } //20 Stealer activated on:
		$a_01_2 = {73 65 6c 66 5f 64 65 6c 65 74 65 2e 62 61 74 } //10 self_delete.bat
	condition:
		((#a_01_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}