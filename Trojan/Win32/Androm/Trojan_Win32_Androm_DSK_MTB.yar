
rule Trojan_Win32_Androm_DSK_MTB{
	meta:
		description = "Trojan:Win32/Androm.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 30 8b 8c 24 ?? ?? ?? ?? 89 38 5f 5e 89 68 04 5d 5b 33 cc e8 ?? ?? ?? ?? 81 c4 2c 08 00 00 c3 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}