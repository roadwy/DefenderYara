
rule Trojan_Win64_Trickbot_SKE{
	meta:
		description = "Trojan:Win64/Trickbot.SKE,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {c0 e2 04 8a ?? ?? ?? 8b ?? c0 ?? 02 80 ?? 0f [0-01] 0a ?? 88 ?? ?? ?? c0 ?? 06 02 ?? ?? ?? 88 90 0a 4a 00 48 83 ?? 01 48 83 ?? 04 75 ?? 8a [0-04] 8a ?? ?? ?? c0 ?? 02 [0-01] 8b ?? c0 ?? 04 [0-02] 03 0a ?? 88 } //30
		$a_03_1 = {0c 41 41 41 41 90 09 1c 00 81 ?? 41 41 41 41 75 ?? 81 ?? 04 41 41 41 41 75 ?? 81 ?? 08 41 41 41 41 75 } //10
		$a_03_2 = {fd ff ff 7f 74 ?? 49 83 ?? 01 48 83 ?? 01 49 8b ?? 75 ?? eb 90 0a 30 00 47 0f ?? ?? ?? 66 45 ?? ?? 74 ?? 66 44 ?? ?? 48 83 ?? 02 4c ?? ?? ff 49 81 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10) >=50
 
}