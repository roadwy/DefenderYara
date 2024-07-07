
rule Trojan_Win32_SmokeLoader_GDT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GDT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e0 90 01 01 89 7d 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 03 45 90 01 01 89 45 90 01 01 83 0d 90 01 04 ff 81 45 90 01 05 8b c7 c1 e8 90 01 01 03 45 90 01 01 c7 05 90 01 04 19 36 6b ff 33 45 90 01 01 31 45 90 01 01 2b 75 90 01 01 ff 4d 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}