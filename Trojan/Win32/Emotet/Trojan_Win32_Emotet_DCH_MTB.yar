
rule Trojan_Win32_Emotet_DCH_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8a 11 03 c2 99 b9 ?? ?? ?? ?? f7 f9 } //20
		$a_02_1 = {55 8b ec 8b 45 ?? 0b 45 ?? 8b 4d ?? f7 d1 8b 55 ?? f7 d2 0b ca 23 c1 } //20
	condition:
		((#a_02_0  & 1)*20+(#a_02_1  & 1)*20) >=40
 
}