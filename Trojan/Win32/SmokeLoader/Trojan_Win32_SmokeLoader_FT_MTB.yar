
rule Trojan_Win32_SmokeLoader_FT_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 8b 45 0c 53 56 8b 75 08 03 c6 89 45 08 8b 45 14 33 db 89 18 8a 16 8b 45 10 57 8b ce 80 fa 11 } //1
		$a_01_1 = {8a 11 88 10 40 41 4f } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}