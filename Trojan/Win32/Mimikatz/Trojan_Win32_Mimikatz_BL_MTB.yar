
rule Trojan_Win32_Mimikatz_BL_MTB{
	meta:
		description = "Trojan:Win32/Mimikatz.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 04 39 84 c0 74 09 3c be 74 05 34 be 88 04 39 41 3b ce 72 } //00 00 
	condition:
		any of ($a_*)
 
}