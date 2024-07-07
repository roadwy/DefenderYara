
rule Trojan_Win32_KillMBR_GPA_MTB{
	meta:
		description = "Trojan:Win32/KillMBR.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {50 64 89 25 00 00 00 00 83 ec 68 53 56 57 89 65 e8 33 db 89 5d fc 6a 02 ff 15 34 10 40 } //2
		$a_81_1 = {53 61 72 63 6f 6d 41 49 20 4c 33 2e 65 78 65 } //2 SarcomAI L3.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}