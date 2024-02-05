
rule Trojan_Win32_mint_RDD_MTB{
	meta:
		description = "Trojan:Win32/mint.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 c1 ba 57 41 0e 98 89 c8 f7 ea 8d 04 0a c1 f8 08 89 c2 89 c8 c1 f8 1f } //00 00 
	condition:
		any of ($a_*)
 
}