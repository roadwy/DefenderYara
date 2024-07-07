
rule Trojan_Win32_Smokeloader_GMJ_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.GMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d6 c1 ea 05 03 54 24 90 01 01 c7 05 90 01 04 19 36 6b ff 33 d3 31 54 24 90 01 01 c7 05 90 01 08 8b 44 24 90 01 01 29 44 24 90 01 01 81 c7 90 01 04 ff 4c 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}