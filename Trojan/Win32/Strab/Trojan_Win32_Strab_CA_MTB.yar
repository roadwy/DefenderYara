
rule Trojan_Win32_Strab_CA_MTB{
	meta:
		description = "Trojan:Win32/Strab.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 74 24 10 0f b6 4c 24 1b 8b 54 24 28 0f af f1 8b 4c 24 2c b9 08 03 4a 59 2b ca f7 d6 f7 d1 33 f1 8b 0d ?? ?? ?? ?? 2b 0d ?? ?? ?? ?? f7 d6 0f af f1 89 35 ?? ?? ?? ?? 48 75 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}