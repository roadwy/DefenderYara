
rule Trojan_Win32_Emotet_SQ_MSR{
	meta:
		description = "Trojan:Win32/Emotet.SQ!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {7a 63 73 64 41 53 6b 78 78 46 44 7a 63 73 54 68 55 } //1 zcsdASkxxFDzcsThU
		$a_01_1 = {55 73 65 72 5c 44 65 73 6b 74 6f 70 5c 32 30 30 38 5c 41 5f 33 44 5f 63 6c 6f 63 6b 31 35 39 35 38 37 36 32 32 30 30 33 5c 52 65 6c 65 61 73 65 5c 33 44 20 52 50 47 2e 70 64 62 } //1 User\Desktop\2008\A_3D_clock159587622003\Release\3D RPG.pdb
		$a_01_2 = {53 48 55 54 44 4f 57 4e } //1 SHUTDOWN
		$a_01_3 = {6d 73 67 5f 65 78 69 74 } //1 msg_exit
		$a_01_4 = {64 6c 6c 6f 6e 65 78 69 74 } //1 dllonexit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Emotet_SQ_MSR_2{
	meta:
		description = "Trojan:Win32/Emotet.SQ!MSR,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b c7 33 d2 83 c4 04 f7 f1 8a 04 1f 8a 54 55 00 32 c2 88 04 1f 8b 44 24 1c 47 3b f8 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}