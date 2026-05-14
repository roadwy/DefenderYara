
rule Trojan_Win32_Lazy_SXI_MTB{
	meta:
		description = "Trojan:Win32/Lazy.SXI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 45 80 2b c1 89 4d 8c 99 f7 bd 74 ff ff ff 6b c0 18 89 45 88 3d 00 10 00 00 } //10
		$a_03_1 = {33 c0 8b f4 89 65 ?? 89 b5 ?? ?? ?? ?? 8b fe ab ab ab ab 33 c0 88 06 } //5
		$a_80_2 = {43 3a 5c 55 73 65 72 73 5c 41 2e 53 6f 67 61 63 68 65 76 5c 69 70 32 61 77 67 5c 69 6e 63 6c 75 64 65 2f 6a 73 6f 6e 2e 68 70 70 } //C:\Users\A.Sogachev\ip2awg\include/json.hpp  1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5+(#a_80_2  & 1)*1) >=16
 
}