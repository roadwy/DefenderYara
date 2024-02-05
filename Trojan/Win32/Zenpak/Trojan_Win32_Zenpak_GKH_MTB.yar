
rule Trojan_Win32_Zenpak_GKH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 88 5d ec c7 45 90 01 01 49 6e 74 65 c7 45 90 01 01 72 6e 65 74 c7 45 90 01 01 43 6f 6e 6e c7 45 90 01 01 65 63 74 00 c7 45 90 01 01 46 74 70 4f c7 45 90 01 01 70 65 6e 46 c7 45 90 01 01 69 6c 65 00 c7 45 90 01 01 49 6e 74 65 c7 45 90 01 01 72 6e 65 74 c7 45 90 01 01 52 65 61 64 c7 45 90 01 01 46 69 6c 65 88 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}