
rule Trojan_Win32_Copak_RPY_MTB{
	meta:
		description = "Trojan:Win32/Copak.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 10 40 21 fe 89 ff 39 d8 75 e2 c3 8d 14 0a 8b 12 47 } //00 00 
	condition:
		any of ($a_*)
 
}