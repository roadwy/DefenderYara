
rule Trojan_Win32_Lokibot_UIO_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.UIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 54 5a 73 42 69 32 63 68 64 00 00 52 4c 32 70 45 6b 6f 4b 54 59 } //00 00 
	condition:
		any of ($a_*)
 
}