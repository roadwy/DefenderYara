
rule Trojan_Win32_RiseProStealer_ADG_MTB{
	meta:
		description = "Trojan:Win32/RiseProStealer.ADG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 48 0c 89 8d 74 fd ff ff 8b 95 74 fd ff ff 8b 42 0c 89 85 70 fd ff ff 8b 8d 70 fd ff ff 89 8d d8 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}