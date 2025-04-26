
rule Trojan_Win32_Farfli_CCHZ_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CCHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b e5 5d c3 6a 00 6a 02 c7 85 ?? ?? ?? ?? 2c 02 00 00 ff 15 ?? ?? ?? ?? 8b f8 83 ff ff 0f 84 ?? ?? 00 00 8d 85 ?? ?? ?? ?? 50 57 ff 15 ?? ?? 42 00 8b 35 ?? ?? 42 00 85 c0 74 59 8b 1d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}