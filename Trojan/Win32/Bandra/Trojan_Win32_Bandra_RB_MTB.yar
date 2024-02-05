
rule Trojan_Win32_Bandra_RB_MTB{
	meta:
		description = "Trojan:Win32/Bandra.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe c7 0f b6 f7 8a 1c 06 02 d3 88 55 0b 0f b6 d2 0f b6 0c 02 88 0c 06 88 1c 02 0f b6 0c 06 0f b6 d3 03 d1 0f b6 ca 8b 55 fc 0f b6 0c 01 30 0c 17 47 8a 55 0b 3b 7d f8 72 c7 } //00 00 
	condition:
		any of ($a_*)
 
}