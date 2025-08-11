
rule Trojan_Win32_Guloader_AM_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {39 cb d9 d0 [0-08] 75 90 0a 50 00 4a [0-15] 29 db [0-15] 0b 1a [0-20] 39 cb d9 d0 [0-08] 75 } //1
		$a_03_1 = {46 85 ff 8b 0f [0-08] 0f 6e c6 [0-08] 0f 6e c9 [0-08] 0f ef c8 [0-08] 0f 7e c9 [0-08] 39 c1 [0-08] 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}