
rule Backdoor_Win32_Farfli_GIC_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b0 6c 88 44 24 1a 88 44 24 1b 68 ?? ?? ?? ?? 8d 44 24 14 33 db 50 c6 44 24 ?? 44 c6 44 24 ?? 56 c6 44 24 ?? 50 c6 44 24 ?? 49 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 88 5c 24 ?? ff d6 } //10
		$a_01_1 = {53 74 61 72 74 75 70 5c 68 61 6f 35 36 37 2e 65 78 65 } //1 Startup\hao567.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}