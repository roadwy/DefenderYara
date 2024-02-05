
rule Trojan_Win32_Zapchast_AH_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {83 e0 1f 6a 20 59 2b c8 8b 45 08 d3 c8 } //05 00 
		$a_01_1 = {58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 7c 5a 54 58 54 7c 58 59 5a 58 } //00 00 
	condition:
		any of ($a_*)
 
}