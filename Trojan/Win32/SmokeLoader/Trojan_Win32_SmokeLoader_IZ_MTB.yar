
rule Trojan_Win32_SmokeLoader_IZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.IZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 65 60 8b 45 90 01 01 81 6d 90 01 05 81 6d 90 01 05 81 45 90 01 05 81 6d 90 01 05 8b 45 90 01 01 8b 4d 90 01 01 31 08 83 c5 90 00 } //1
		$a_03_1 = {52 8d 45 0c 50 e8 90 01 04 8b 45 90 01 01 33 45 90 01 01 83 65 90 01 02 2b f0 8b 45 90 01 01 01 45 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}