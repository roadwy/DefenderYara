
rule Trojan_Win32_StealC_KHU_MTB{
	meta:
		description = "Trojan:Win32/StealC.KHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 0d 54 ad 45 00 69 c9 fd 43 03 00 81 c1 c3 9e 26 00 89 0d 54 90 01 01 45 00 8a 15 56 90 01 01 45 00 30 14 33 83 ff 0f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}