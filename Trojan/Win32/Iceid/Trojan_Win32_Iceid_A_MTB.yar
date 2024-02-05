
rule Trojan_Win32_Iceid_A_MTB{
	meta:
		description = "Trojan:Win32/Iceid.A!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 f7 75 14 8b 45 08 0f be 0c 10 8b 55 0c 03 55 fc 0f b6 02 33 c1 8b 4d 0c 03 4d fc 88 01 } //00 00 
	condition:
		any of ($a_*)
 
}