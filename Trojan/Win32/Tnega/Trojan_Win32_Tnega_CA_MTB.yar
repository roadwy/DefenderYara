
rule Trojan_Win32_Tnega_CA_MTB{
	meta:
		description = "Trojan:Win32/Tnega.CA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {39 ff 74 01 ea 31 06 81 c1 [0-04] 2c 81 c1 [0-04] 81 c6 04 00 00 00 81 c2 [0-04] 49 39 fe 75 dc } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}