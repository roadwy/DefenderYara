
rule Trojan_Win32_SSLoad_ZZ_MTB{
	meta:
		description = "Trojan:Win32/SSLoad.ZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {b9 fc ff ff ff 8b 91 ?? ?? ?? ?? 33 54 08 ?? 89 54 0c ?? 83 c1 ?? 83 f9 ?? 72 ea } //1
		$a_01_1 = {50 4f 53 54 2a 2f 2a 48 54 54 50 2f 31 2e 31 43 6f 6e 74 65 6e 74 2d 54 79 70 65 3a 20 61 70 70 6c 69 63 61 74 69 6f 6e 2f 6a 73 6f 6e } //1 POST*/*HTTP/1.1Content-Type: application/json
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}