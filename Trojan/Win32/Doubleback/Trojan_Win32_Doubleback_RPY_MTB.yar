
rule Trojan_Win32_Doubleback_RPY_MTB{
	meta:
		description = "Trojan:Win32/Doubleback.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 f2 48 7f cc d6 7f bb 73 b9 8b 85 18 ff ff ff 33 d2 f7 75 14 8b 45 10 0f b6 0c 10 8b 55 08 03 95 18 ff ff ff 0f b6 02 2b c1 8b 4d 08 03 8d 18 ff ff ff 88 01 e9 } //00 00 
	condition:
		any of ($a_*)
 
}