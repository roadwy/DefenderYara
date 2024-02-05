
rule Trojan_Win32_Fsysna_GM_MTB{
	meta:
		description = "Trojan:Win32/Fsysna.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c1 99 f7 fe 8a 44 14 0c 30 04 19 41 81 f9 90 02 04 7c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}