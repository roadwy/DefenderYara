
rule Trojan_Win32_RaccoonStealer_CCBK_MTB{
	meta:
		description = "Trojan:Win32/RaccoonStealer.CCBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 02 8d 52 ?? 03 c7 89 04 8b 41 3b ce 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}