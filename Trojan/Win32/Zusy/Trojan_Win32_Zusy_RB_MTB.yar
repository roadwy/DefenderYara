
rule Trojan_Win32_Zusy_RB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba 7e 07 00 00 8b c1 83 e0 03 8a 80 90 01 04 30 81 90 01 04 41 3b ca 72 ea 53 56 57 6a 40 68 00 30 00 00 52 6a 00 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}