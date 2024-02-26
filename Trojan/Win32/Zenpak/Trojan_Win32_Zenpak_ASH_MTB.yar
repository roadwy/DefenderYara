
rule Trojan_Win32_Zenpak_ASH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 f0 0a 48 48 8d 05 90 02 04 31 18 83 f2 02 8d 05 90 02 04 31 30 40 8d 05 90 00 } //01 00 
		$a_03_1 = {01 d0 8d 05 90 02 04 01 20 83 ea 0a 83 ea 0a ba 01 00 00 00 31 d0 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}