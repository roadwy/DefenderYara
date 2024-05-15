
rule Trojan_Win32_Unruy_GZX_MTB{
	meta:
		description = "Trojan:Win32/Unruy.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {48 96 1a 01 01 b9 90 01 04 67 bf 90 01 04 12 8a 90 01 04 a3 90 01 04 6d 90 01 01 32 27 64 e0 f9 34 f4 90 01 01 01 5c 51 4f 14 7c 0d 90 01 04 4f 87 61 83 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}