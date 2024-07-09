
rule Trojan_Win32_Emotet_DHG_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 0c 7d 1a 8b 55 08 03 55 fc 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 eb d5 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}