
rule Trojan_Win32_Smokeloader_GMN_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 c7 05 90 01 04 6f 74 65 63 c7 05 90 01 04 75 61 6c 50 c6 05 90 01 04 72 66 c7 05 90 01 04 74 00 c7 45 90 01 01 20 00 00 00 83 45 90 01 01 20 8d 45 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}