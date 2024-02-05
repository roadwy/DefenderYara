
rule Trojan_Win32_NSISInject_PRF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.PRF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 45 d4 8a 04 05 00 60 90 01 01 00 88 45 d3 8b 45 c8 8b 4d cc 8a 04 08 88 45 d2 0f b6 45 d3 c1 f8 03 0f b6 4d d3 c1 e1 05 09 c8 0f b6 4d d2 31 c8 88 c1 8b 45 d4 88 0c 05 00 60 90 01 01 00 8b 45 cc 83 c0 01 b9 0d 00 00 00 99 f7 f9 89 55 cc 8b 45 d4 83 c0 01 89 45 d4 81 7d d4 90 01 02 00 00 0f 83 05 00 00 00 e9 99 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}