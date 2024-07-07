
rule Trojan_Win32_Barys_RB_MTB{
	meta:
		description = "Trojan:Win32/Barys.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 20 03 54 24 08 8a 6d 00 8a 22 30 e5 88 6d 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}