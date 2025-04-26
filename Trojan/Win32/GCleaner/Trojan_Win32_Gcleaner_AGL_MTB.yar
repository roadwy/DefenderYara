
rule Trojan_Win32_Gcleaner_AGL_MTB{
	meta:
		description = "Trojan:Win32/Gcleaner.AGL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 c0 30 98 64 0f 45 00 40 83 f8 0f 72 } //2
		$a_01_1 = {80 35 30 0d 45 00 2e 80 35 31 0d 45 00 2e 80 35 32 0d 45 00 2e 80 35 33 0d 45 00 2e 80 35 34 0d 45 00 2e 80 35 35 0d 45 00 2e 80 35 36 0d 45 00 2e 80 35 37 0d 45 00 2e 80 35 38 0d 45 00 2e 34 2e a2 39 0d 45 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}