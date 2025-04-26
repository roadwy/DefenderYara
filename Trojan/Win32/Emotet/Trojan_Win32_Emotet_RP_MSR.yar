
rule Trojan_Win32_Emotet_RP_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RP!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 55 73 65 72 73 5c 55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 32 30 30 38 5c 57 69 6e 33 32 5f 2d 5f 49 45 31 32 30 31 34 35 38 31 39 32 30 30 32 5c 52 65 6c 65 61 73 65 5c 49 45 5f 4d 45 4e 55 42 41 52 2e 70 64 62 } //2 c:\Users\User\Desktop\2008\Win32_-_IE1201458192002\Release\IE_MENUBAR.pdb
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_RP_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.RP!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 33 45 d4 89 45 f8 8b 45 f8 c1 e0 1f c1 f8 1f 89 c2 81 e2 96 30 07 77 8b 45 f8 c1 e0 1e c1 f8 1f 25 2c 61 0e ee 31 c2 8b 45 f8 c1 e0 1d c1 f8 1f 25 19 c4 6d 07 31 c2 8b 45 f8 c1 e0 1c c1 f8 1f 25 32 88 db 0e 31 c2 8b 45 f8 c1 e0 1b c1 f8 1f 25 64 10 b7 1d 31 c2 8b 45 f8 c1 e0 1a c1 f8 1f 25 c8 20 6e 3b 31 c2 8b 45 f8 c1 e0 19 c1 f8 1f 25 90 41 dc 76 31 c2 8b 45 f8 c1 e0 18 c1 f8 1f 25 20 83 b8 ed 31 d0 89 45 d0 8b 45 f8 c1 e8 08 33 45 d0 89 45 f8 ff 45 fc 8b 55 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}