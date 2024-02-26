
rule Trojan_Win32_StealC_RDD_MTB{
	meta:
		description = "Trojan:Win32/StealC.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 03 03 d9 25 61 6c 20 63 0d 00 02 4e 0c 89 03 03 d9 } //00 00 
	condition:
		any of ($a_*)
 
}