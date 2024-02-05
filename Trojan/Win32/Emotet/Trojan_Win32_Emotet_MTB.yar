
rule Trojan_Win32_Emotet_MTB{
	meta:
		description = "Trojan:Win32/Emotet!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 64 a1 30 00 00 00 89 45 fc 8b 45 fc 8b e5 5d } //01 00 
		$a_01_1 = {55 8b ec 56 57 8b 75 08 33 ff 33 c0 fc ac 84 c0 74 07 c1 cf 0d 03 f8 eb f4 8b c7 5f 5e 5d } //00 00 
	condition:
		any of ($a_*)
 
}