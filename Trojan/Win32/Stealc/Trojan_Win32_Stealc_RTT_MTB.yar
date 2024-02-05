
rule Trojan_Win32_Stealc_RTT_MTB{
	meta:
		description = "Trojan:Win32/Stealc.RTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 00 3c 40 7e 90 01 01 8b 45 08 0f b6 00 3c 5a 7f 90 01 01 8b 45 08 0f b6 00 83 c8 20 0f be c0 eb 90 01 01 8b 45 08 0f b6 00 0f be c0 31 45 f0 83 45 08 01 83 45 f4 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}