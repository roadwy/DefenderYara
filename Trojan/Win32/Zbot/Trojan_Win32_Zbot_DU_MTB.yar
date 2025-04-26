
rule Trojan_Win32_Zbot_DU_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 c1 c1 c0 f0 c0 35 c1 10 c0 45 c0 c0 10 31 30 20 35 31 20 c1 c3 8b 31 8b c1 20 35 f0 c0 f0 20 c0 31 30 10 31 20 31 c0 31 8b f0 c0 30 35 45 30 c1 30 30 8b 30 c3 } //1
		$a_81_1 = {43 3a 5c 55 73 65 72 73 5c 67 65 6f 72 67 65 5c 44 65 73 6b 74 6f 70 5c 64 61 77 69 64 2e 65 78 65 } //1 C:\Users\george\Desktop\dawid.exe
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}