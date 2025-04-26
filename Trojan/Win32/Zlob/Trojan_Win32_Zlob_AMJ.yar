
rule Trojan_Win32_Zlob_AMJ{
	meta:
		description = "Trojan:Win32/Zlob.AMJ,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 78 1a 8b 4c 24 08 2b ce 8a 94 01 ?? ?? 00 10 32 54 24 0c 48 88 90 90 ?? ?? 00 10 79 ec } //3
		$a_01_1 = {d5 c2 9e d3 df dd 00 65 78 70 6c 6f 72 65 72 2e } //2
		$a_01_2 = {2e 70 68 70 3f 71 71 3d 25 73 } //1 .php?qq=%s
		$a_00_3 = {72 00 65 00 73 00 3a 00 2f 00 2f 00 25 00 73 00 } //1 res://%s
		$a_01_4 = {2e 64 6c 6c 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 } //1 搮汬䐀汬慃啮汮慯
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}