
rule Trojan_Win32_Smokeloader_HNH_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.HNH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {36 8e ea 1e c7 45 ?? a7 a1 63 15 c7 45 } //1
		$a_01_1 = {6d 00 73 00 69 00 6d 00 67 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 } //1 msimg32.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}