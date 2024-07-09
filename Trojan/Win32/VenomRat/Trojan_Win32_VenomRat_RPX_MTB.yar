
rule Trojan_Win32_VenomRat_RPX_MTB{
	meta:
		description = "Trojan:Win32/VenomRat.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 05 0c 00 0f 80 9b 00 00 00 0f bf c8 51 ff 15 ?? ?? ?? ?? 8b d0 8d 4d d8 ff d7 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}