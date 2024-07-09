
rule Trojan_Win32_Lokibot_YA_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {e8 f8 d0 f9 ff 90 90 33 c0 90 90 90 90 33 db 90 90 c6 44 ?? ?? ?? 8b d3 8b fe 03 fa 90 90 8a 90 90 ?? ?? ?? 00 32 54 ?? ?? 88 17 40 90 90 40 90 90 43 81 ?? ?? ?? 00 00 75 da 90 90 90 90 8b c6 e8 12 ff ff ff 90 90 90 90 59 5a 5f 5e 5b c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}