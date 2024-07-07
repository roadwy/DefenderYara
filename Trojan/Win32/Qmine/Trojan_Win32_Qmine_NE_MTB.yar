
rule Trojan_Win32_Qmine_NE_MTB{
	meta:
		description = "Trojan:Win32/Qmine.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 76 63 68 6f 73 74 6c 6f 6e 67 2e 65 78 65 } //1 :\ProgramData\svchostlong.exe
		$a_02_1 = {63 6d 64 20 2f 63 20 64 65 6c 20 2f 61 20 2f 66 20 2f 71 20 90 01 01 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 2a 2e 74 78 74 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}