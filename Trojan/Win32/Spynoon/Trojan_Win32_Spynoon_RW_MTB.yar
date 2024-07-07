
rule Trojan_Win32_Spynoon_RW_MTB{
	meta:
		description = "Trojan:Win32/Spynoon.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 cd cc cc cc 83 c4 04 f7 e6 8b c6 c1 ea 03 8d 0c 92 03 c9 2b c1 8a 80 90 01 04 30 04 1e 46 ff 07 3b f5 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}