
rule Trojan_Win32_SmokeLoader_CME_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 89 4d 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 33 45 90 01 01 83 25 90 01 05 33 45 90 01 01 50 90 00 } //1
		$a_03_1 = {c1 e8 05 c7 05 90 01 08 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 ff 75 90 01 01 8d 45 90 01 01 50 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}