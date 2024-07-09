
rule Trojan_Win32_BazarLoader_LKA_MTB{
	meta:
		description = "Trojan:Win32/BazarLoader.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 68 ?? ?? 00 00 6a 00 ff 15 } //1
		$a_03_1 = {78 61 6d 70 70 5c 68 74 64 6f 63 73 [0-f0] 4c 6f 61 64 65 72 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}