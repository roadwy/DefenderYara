
rule Trojan_Win32_Sabsik_RT_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c1 72 8b 90 01 02 99 f7 7d 90 01 01 8b 45 90 01 01 0f be 14 10 33 ca 8b 45 90 01 01 03 45 90 01 01 88 08 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}