
rule Trojan_Win32_ICLoader_RH_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 5e 5b 5d c3 8b c6 5e 5b 5d c3 90 90 90 90 90 90 90 90 90 90 90 90 90 55 8b ec 51 53 56 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}