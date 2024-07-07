
rule Trojan_Win32_Mint_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Mint.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 eb 15 6a 04 68 00 10 00 00 57 56 ff 15 88 67 41 00 85 c0 74 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}