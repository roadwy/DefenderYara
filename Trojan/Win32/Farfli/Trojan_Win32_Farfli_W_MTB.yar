
rule Trojan_Win32_Farfli_W_MTB{
	meta:
		description = "Trojan:Win32/Farfli.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {f6 d8 fe ca fe c0 d0 da 34 90 01 01 84 f7 c1 da 90 01 01 f8 28 da 30 c3 fe ca 66 0f bd d6 0f b6 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}