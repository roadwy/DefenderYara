
rule Trojan_Win32_Pterodo_YAA_MTB{
	meta:
		description = "Trojan:Win32/Pterodo.YAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 08 5b 89 5d fc 8b 45 2c 8b 7d 0c 89 7d 14 8b 4d 24 8a 54 08 ff 84 d2 74 cf 30 14 08 eb ca } //00 00 
	condition:
		any of ($a_*)
 
}