
rule Trojan_Win32_Zusy_AMAI_MTB{
	meta:
		description = "Trojan:Win32/Zusy.AMAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 30 04 39 8b c2 8b 4c 24 ?? 2b ca 81 f9 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}