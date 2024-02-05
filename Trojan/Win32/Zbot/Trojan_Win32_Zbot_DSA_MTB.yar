
rule Trojan_Win32_Zbot_DSA_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DSA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 07 03 ce 88 02 4e 4b 03 f0 f7 d0 42 48 f7 d1 4e 47 f7 d9 0b db 75 e8 } //00 00 
	condition:
		any of ($a_*)
 
}