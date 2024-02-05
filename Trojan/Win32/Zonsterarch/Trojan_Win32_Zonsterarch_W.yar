
rule Trojan_Win32_Zonsterarch_W{
	meta:
		description = "Trojan:Win32/Zonsterarch.W,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 7d d8 30 04 00 00 0f 83 ab 01 00 00 8b 55 f4 83 c2 01 } //00 00 
	condition:
		any of ($a_*)
 
}