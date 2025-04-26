
rule Trojan_Win32_Hancitor_ARAX_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 0f be 0c 10 8b 55 08 03 55 fc 0f be 02 33 c1 8b 4d 08 03 4d fc 88 01 eb c7 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}