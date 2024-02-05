
rule Trojan_Win32_Dridex_KD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.KD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {33 d1 8b c2 a3 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 5d 90 00 } //0a 00 
		$a_00_1 = {8b 08 2b ca 8b 55 08 89 0a 5e 8b e5 5d } //00 00 
	condition:
		any of ($a_*)
 
}