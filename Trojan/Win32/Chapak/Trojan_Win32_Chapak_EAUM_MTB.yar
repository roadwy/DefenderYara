
rule Trojan_Win32_Chapak_EAUM_MTB{
	meta:
		description = "Trojan:Win32/Chapak.EAUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 94 01 3b 2d 0b 00 8b 0d ?? ?? ?? ?? 88 14 01 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}