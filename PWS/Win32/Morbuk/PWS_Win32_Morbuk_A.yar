
rule PWS_Win32_Morbuk_A{
	meta:
		description = "PWS:Win32/Morbuk.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {83 ec 08 89 45 fc 8b 45 fc 25 00 80 00 80 89 45 f8 83 7d f8 00 0f 95 c0 0f b6 c0 } //2
		$a_01_1 = {5b 44 4f 57 4e 5d 00 5b 53 4e 41 50 5d } //1
		$a_01_2 = {5b 46 32 32 5d 00 5b 46 32 33 5d } //1
		$a_01_3 = {68 6b 62 2e 64 6c 6c 00 45 6e 64 48 6f 6f 6b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}