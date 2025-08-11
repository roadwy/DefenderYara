
rule Trojan_Win32_Allinonekeylogger_PGAK_MTB{
	meta:
		description = "Trojan:Win32/Allinonekeylogger.PGAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c1 33 d2 f7 f6 41 0f b6 82 ?? ?? ?? ?? 03 c3 33 d2 f7 75 fc 8b 45 08 03 de 80 c2 ?? 88 54 08 fe 8b 45 0c 3b cf 7e d8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}