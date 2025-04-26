
rule Trojan_Win32_Crysan_SIBC_MTB{
	meta:
		description = "Trojan:Win32/Crysan.SIBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {bb 00 00 00 00 8a 8b ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 74 ?? f6 d1 80 c1 ?? 80 f1 ?? 80 c1 ?? 80 f1 ?? 88 8b 90 1b 00 83 c3 01 90 18 8a 8b 90 1b 00 81 fb 90 1b 01 90 18 66 59 5b 8d 45 ?? 50 6a 40 68 90 1b 01 68 90 1b 00 ff 15 ?? ?? ?? ?? 6a 00 68 90 1b 00 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}