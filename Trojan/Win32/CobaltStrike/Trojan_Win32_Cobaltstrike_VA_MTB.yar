
rule Trojan_Win32_Cobaltstrike_VA_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 50 52 8b 54 24 10 52 8b 54 24 10 52 8b 0d 4c 30 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}