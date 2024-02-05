
rule Trojan_Win32_Xmrig_NEAB_MTB{
	meta:
		description = "Trojan:Win32/Xmrig.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 45 cc 83 c0 01 8b 4d d0 83 d1 00 89 45 cc 89 4d d0 83 7d d0 00 77 16 72 09 81 7d cc 00 e1 f5 05 73 0b 8b 55 d4 83 c2 01 89 55 d4 eb d2 } //05 00 
		$a_01_1 = {33 c5 89 45 fc 89 4d f4 8b 45 f4 89 45 e8 8b 4d 08 } //00 00 
	condition:
		any of ($a_*)
 
}