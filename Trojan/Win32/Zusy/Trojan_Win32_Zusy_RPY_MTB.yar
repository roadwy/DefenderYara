
rule Trojan_Win32_Zusy_RPY_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b f0 6a 5a 56 ff 15 58 80 65 00 56 6a 00 a3 90 cd 65 00 ff 15 40 83 65 00 a1 90 cd 65 00 6a 48 50 6a 08 ff 15 ec 80 65 00 8b 35 5c 80 65 00 f7 d8 6a 07 } //00 00 
	condition:
		any of ($a_*)
 
}