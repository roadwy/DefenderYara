
rule Trojan_Win32_Omssun{
	meta:
		description = "Trojan:Win32/Omssun,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {85 c0 74 34 8d 44 37 f3 8b f7 3b f8 73 2a b2 84 b1 eb 80 3e e8 75 1c 80 7e 05 85 75 16 80 7e 06 c0 75 10 80 7e 07 0f 75 0a 38 56 08 75 05 38 4e 0d 74 1d 46 3b f0 72 da } //00 00 
	condition:
		any of ($a_*)
 
}