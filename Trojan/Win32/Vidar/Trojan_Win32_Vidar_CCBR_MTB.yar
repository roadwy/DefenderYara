
rule Trojan_Win32_Vidar_CCBR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CCBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 f1 8b 45 90 01 01 8a 0c 02 8b 55 90 01 01 8d 04 1e 32 0c 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}