
rule Trojan_Win32_Vidar_CCBR_MTB{
	meta:
		description = "Trojan:Win32/Vidar.CCBR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8b c6 f7 f1 8b 45 ?? 8a 0c 02 8b 55 ?? 8d 04 1e 32 0c 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}