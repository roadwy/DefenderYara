
rule Trojan_Win32_Lokibot_H_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 [0-1f] 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 6a 00 e8 ?? ?? ?? ff } //1
		$a_02_1 = {8a 04 02 88 45 eb [0-9f] 8a 55 eb 33 c2 [0-20] 8b 55 f0 88 02 [0-20] ff 45 f4 ff 4d e0 0f 85 ?? ?? ff ff } //5
		$a_02_2 = {8a 04 02 88 45 f7 [0-9f] 8a 55 f7 33 c2 [0-20] 8b 55 e4 88 02 [0-20] ff 45 f0 ff 4d e0 0f 85 ?? ?? ff ff } //5
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*5+(#a_02_2  & 1)*5) >=6
 
}