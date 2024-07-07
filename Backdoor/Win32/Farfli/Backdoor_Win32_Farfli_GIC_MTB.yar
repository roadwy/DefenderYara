
rule Backdoor_Win32_Farfli_GIC_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b0 6c 88 44 24 1a 88 44 24 1b 68 90 01 04 8d 44 24 14 33 db 50 c6 44 24 90 01 01 44 c6 44 24 90 01 01 56 c6 44 24 90 01 01 50 c6 44 24 90 01 01 49 c6 44 24 90 01 01 33 c6 44 24 90 01 01 32 c6 44 24 90 01 01 2e c6 44 24 90 01 01 64 88 5c 24 90 01 01 ff d6 90 00 } //10
		$a_01_1 = {53 74 61 72 74 75 70 5c 68 61 6f 35 36 37 2e 65 78 65 } //1 Startup\hao567.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}