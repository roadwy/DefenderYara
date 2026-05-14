
rule Trojan_Win64_DiscordStealer_ND_MTB{
	meta:
		description = "Trojan:Win64/DiscordStealer.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {c6 40 01 00 48 8b b4 24 58 01 00 00 48 89 ac 24 e0 01 00 00 48 8b bc 24 50 01 00 00 48 8d 56 09 c6 84 24 f0 01 00 00 00 48 c7 84 24 e8 01 } //2
		$a_01_1 = {53 74 65 61 6c 65 72 20 42 6f 74 } //1 Stealer Bot
		$a_01_2 = {70 63 69 6e 66 6f 2e 74 78 74 } //1 pcinfo.txt
		$a_01_3 = {77 6d 69 63 20 63 70 75 20 67 65 74 20 50 72 6f 63 65 73 73 6f 72 49 64 } //1 wmic cpu get ProcessorId
		$a_01_4 = {4c 6f 67 69 6e 20 44 61 74 61 } //1 Login Data
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}