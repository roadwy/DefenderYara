
rule Trojan_Win32_Vidar_PAFH_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c8 33 d2 8b c7 f7 f1 8b 45 0c 68 ?? ?? ?? ?? 8a 0c 02 8b 55 f8 32 0c 1a 88 0b } //1
		$a_01_1 = {5c 4d 6f 6e 65 72 6f 5c 77 61 6c 6c 65 74 2e 6b 65 79 73 } //1 \Monero\wallet.keys
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}