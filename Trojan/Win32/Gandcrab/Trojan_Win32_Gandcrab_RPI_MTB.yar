
rule Trojan_Win32_Gandcrab_RPI_MTB{
	meta:
		description = "Trojan:Win32/Gandcrab.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 03 89 75 cc c1 e3 0c 81 6d cc 90 01 04 c1 e3 00 81 45 cc 90 01 04 c1 e8 07 81 6d cc 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}