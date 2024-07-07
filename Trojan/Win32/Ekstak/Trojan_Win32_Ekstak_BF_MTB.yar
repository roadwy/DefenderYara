
rule Trojan_Win32_Ekstak_BF_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c8 8d 34 10 8b 45 0c 8a 0c 11 88 0c 06 8a 8a 90 01 04 84 c9 75 90 01 01 8b 0d 90 01 04 03 ca 03 c1 8a 0d 90 01 04 30 08 83 3d 90 01 04 03 76 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}