
rule Trojan_Win32_Magania_DSK_MTB{
	meta:
		description = "Trojan:Win32/Magania.DSK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 44 1e 01 8a 14 39 46 32 c2 2c 03 bd 06 00 00 00 88 04 39 8b c1 99 f7 fd 85 d2 75 } //00 00 
	condition:
		any of ($a_*)
 
}