
rule Trojan_Win32_Jaik_GIC_MTB{
	meta:
		description = "Trojan:Win32/Jaik.GIC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 45 bc 49 c6 45 bd 6e c6 45 be 74 c6 45 bf 65 c6 45 c0 72 c6 45 c1 6e c6 45 c2 65 c6 45 c3 74 c6 45 c4 52 c6 45 c5 65 c6 45 c6 61 c6 45 c7 64 c6 45 c8 46 c6 45 c9 69 c6 45 ca 6c c6 45 cb 65 } //10
		$a_01_1 = {63 6d 64 20 2f 63 20 73 74 61 72 74 20 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 31 34 35 31 34 } //1 cmd /c start C:\ProgramData\114514
		$a_01_2 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d 20 6d 6d 63 2e 65 78 65 } //1 cmd /c taskkill /f /t /im mmc.exe
		$a_80_3 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 31 31 34 35 31 34 } //C:\ProgramData\114514  1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_80_3  & 1)*1) >=13
 
}