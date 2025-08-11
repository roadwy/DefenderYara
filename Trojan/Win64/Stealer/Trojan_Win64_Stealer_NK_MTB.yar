
rule Trojan_Win64_Stealer_NK_MTB{
	meta:
		description = "Trojan:Win64/Stealer.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 48 89 84 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 48 89 84 24 ?? 00 00 00 48 8b 8c 24 ?? 00 00 00 e8 } //2
		$a_03_1 = {48 8d 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 48 8d 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 48 8d 8c 24 ?? 00 00 00 e8 ?? ?? 00 00 e9 e3 01 00 00 } //1
		$a_01_2 = {54 65 6c 65 67 72 61 6d 20 44 65 73 6b 74 6f 70 } //1 Telegram Desktop
		$a_01_3 = {52 6f 61 6d 69 6e 67 } //1 Roaming
		$a_01_4 = {55 53 45 52 50 52 4f 46 49 4c 45 } //1 USERPROFILE
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}