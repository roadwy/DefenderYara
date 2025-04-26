
rule Trojan_WinNT_Dogrobot_F{
	meta:
		description = "Trojan:WinNT/Dogrobot.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 0c 8b 50 3c 8b 41 10 8b 08 a1 ?? ?? ?? ?? 39 48 08 76 1f 8b 30 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 02 89 04 8e 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 8b 4d 0c 8b 71 18 83 61 1c 00 32 d2 ff 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}