
rule Trojan_Win32_Barys_RC_MTB{
	meta:
		description = "Trojan:Win32/Barys.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 6d 00 8a 0e 31 f6 30 cd 88 6d 00 8b 5c 24 04 83 c3 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}