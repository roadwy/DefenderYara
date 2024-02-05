
rule Trojan_Win32_Zenpak_GFU_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GFU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {01 18 8d 05 90 01 04 31 30 8d 05 90 01 04 ff e0 31 c2 01 3d 90 01 04 b8 09 00 00 00 4a 83 c2 0a 31 2d 90 01 04 eb 90 00 } //01 00 
		$a_80_1 = {73 6f 6e 65 6d 69 64 73 74 66 6f 72 33 77 66 72 6f 6d } //sonemidstfor3wfrom  00 00 
	condition:
		any of ($a_*)
 
}