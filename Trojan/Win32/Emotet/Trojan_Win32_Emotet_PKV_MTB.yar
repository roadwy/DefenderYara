
rule Trojan_Win32_Emotet_PKV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {0f b6 04 37 03 c1 99 b9 c3 10 00 00 f7 f9 0f b6 04 32 8b 54 24 10 0f be 0c 2a 51 50 e8 90 01 04 88 45 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}