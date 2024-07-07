
rule Trojan_Win32_Tnega_MT_MTB{
	meta:
		description = "Trojan:Win32/Tnega.MT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 0f b6 90 01 01 8b 90 02 05 0f 90 02 07 30 90 02 02 43 3b 90 02 05 72 90 09 21 00 0f 90 02 07 88 90 02 06 88 90 02 06 0f 90 02 07 0f b6 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}