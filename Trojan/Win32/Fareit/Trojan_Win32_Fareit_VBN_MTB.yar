
rule Trojan_Win32_Fareit_VBN_MTB{
	meta:
		description = "Trojan:Win32/Fareit.VBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {90 89 1e a1 f0 cb 46 00 03 06 8a 00 90 90 34 2b 8b 15 f0 cb 46 00 03 16 88 02 43 } //00 00 
	condition:
		any of ($a_*)
 
}