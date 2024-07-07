
rule Worm_Win32_Phorpiex_X{
	meta:
		description = "Worm:Win32/Phorpiex.X,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 77 69 6e 73 76 63 6f 6e 2e 74 78 74 } //1 %s\winsvcon.txt
		$a_01_1 = {80 f9 30 7c 1f 80 f9 39 7f 1a 0f be c9 83 f1 30 8d 14 92 46 8d 14 51 8a 0e bf 01 00 00 00 84 c9 75 de } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}