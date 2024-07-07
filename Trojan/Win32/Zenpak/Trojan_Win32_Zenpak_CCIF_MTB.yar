
rule Trojan_Win32_Zenpak_CCIF_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 45 0c 8a 4d 08 30 c8 a2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}