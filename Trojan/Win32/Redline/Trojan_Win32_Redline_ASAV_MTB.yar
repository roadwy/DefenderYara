
rule Trojan_Win32_Redline_ASAV_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 12 ff 74 24 ?? 8b cb e8 ?? ?? 00 00 8b cb e8 ?? ?? 00 00 80 b6 } //1
		$a_01_1 = {4f 6e 6a 68 72 65 62 79 75 75 58 62 68 6e 41 5a 75 79 74 74 32 76 6a 63 68 6a 73 64 } //1 OnjhrebyuuXbhnAZuytt2vjchjsd
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}