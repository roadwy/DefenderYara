
rule Trojan_Win32_Disco_GAA_MTB{
	meta:
		description = "Trojan:Win32/Disco.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 75 e8 8b 4d dc b8 ?? ?? ?? ?? 8b 7d d8 2b cf ff 85 ?? ?? ?? ?? 83 85 ?? ?? ?? ?? 18 f7 e9 c1 fa 02 8b c2 c1 e8 1f 03 c2 39 85 ac fe ff ff 8b 85 } //10
		$a_01_1 = {64 69 73 63 6f 72 64 2e 63 6f 6d 2f 61 70 69 2f 77 65 62 68 6f 6f 6b 73 } //1 discord.com/api/webhooks
		$a_01_2 = {5c 64 69 73 63 6f 72 64 63 61 6e 61 72 79 } //1 \discordcanary
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}