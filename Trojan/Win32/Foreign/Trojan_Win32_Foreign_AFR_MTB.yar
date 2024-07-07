
rule Trojan_Win32_Foreign_AFR_MTB{
	meta:
		description = "Trojan:Win32/Foreign.AFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 0c 33 c0 8d 4c 24 90 01 01 51 8d 54 24 90 01 01 52 50 50 68 00 01 00 00 50 50 50 57 50 89 44 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}