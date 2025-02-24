
rule Trojan_Win32_Glupteba_EAHC_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.EAHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d a4 24 00 00 00 00 8d 49 00 8b 15 ?? ?? ?? ?? 8a 8c 02 3b 2d 0b 00 8b 15 ?? ?? ?? ?? 88 0c 02 8b 15 ?? ?? ?? ?? 40 3b c2 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}