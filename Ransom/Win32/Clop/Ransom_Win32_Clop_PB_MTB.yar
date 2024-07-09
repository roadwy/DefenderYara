
rule Ransom_Win32_Clop_PB_MTB{
	meta:
		description = "Ransom:Win32/Clop.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2d 2d 2d 2d 2d 42 45 47 49 4e 20 50 55 42 4c 49 43 20 4b 45 59 2d 2d 2d 2d 2d } //1 -----BEGIN PUBLIC KEY-----
		$a_01_1 = {52 00 45 00 41 00 44 00 5f 00 4d 00 45 00 5f 00 21 00 21 00 21 00 2e 00 54 00 58 00 54 00 } //1 READ_ME_!!!.TXT
		$a_01_2 = {2e 00 43 00 5f 00 4c 00 5f 00 4f 00 5f 00 50 00 } //1 .C_L_O_P
		$a_01_3 = {25 00 73 00 20 00 72 00 75 00 6e 00 72 00 75 00 6e 00 } //1 %s runrun
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Ransom_Win32_Clop_PB_MTB_2{
	meta:
		description = "Ransom:Win32/Clop.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_01_0 = {26 2a 5e 40 51 44 53 4a 47 49 4f } //10 &*^@QDSJGIO
		$a_01_1 = {26 4a 54 45 48 24 57 48 44 } //10 &JTEH$WHD
		$a_81_2 = {2f 43 20 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 64 6f 6d 61 69 6e 70 72 6f 66 69 6c 65 20 73 74 61 74 65 20 6f 66 66 } //1 /C netsh advfirewall set domainprofile state off
		$a_81_3 = {2f 43 20 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 20 63 75 72 72 65 6e 74 70 72 6f 66 69 6c 65 20 73 74 61 74 65 20 6f 66 66 } //1 /C netsh advfirewall set  currentprofile state off
		$a_81_4 = {2f 43 20 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 70 72 69 76 61 74 65 70 72 6f 66 69 6c 65 20 73 74 61 74 65 20 6f 66 66 } //1 /C netsh advfirewall set privateprofile state off
		$a_81_5 = {2f 43 20 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 70 75 62 6c 69 63 70 72 6f 66 69 6c 65 20 73 74 61 74 65 20 6f 66 66 } //1 /C netsh advfirewall set publicprofile state off
		$a_81_6 = {2f 43 20 6e 65 74 73 68 20 61 64 76 66 69 72 65 77 61 6c 6c 20 73 65 74 20 20 61 6c 6c 70 72 6f 66 69 6c 65 73 20 73 74 61 74 65 20 6f 66 66 } //1 /C netsh advfirewall set  allprofiles state off
		$a_81_7 = {2f 43 20 6e 65 74 73 68 20 66 69 72 65 77 61 6c 6c 20 73 65 74 20 6f 70 6d 6f 64 65 20 6d 6f 64 65 3d 44 49 53 41 42 4c 45 } //1 /C netsh firewall set opmode mode=DISABLE
		$a_01_8 = {26 48 44 47 46 24 57 23 47 53 52 47 48 52 45 47 52 57 } //1 &HDGF$W#GSRGHREGRW
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_01_8  & 1)*1) >=17
 
}
rule Ransom_Win32_Clop_PB_MTB_3{
	meta:
		description = "Ransom:Win32/Clop.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 00 73 00 5c 00 43 00 49 00 6f 00 70 00 52 00 65 00 61 00 64 00 4d 00 65 00 2e 00 74 00 78 00 74 00 } //1 %s\CIopReadMe.txt
		$a_00_1 = {73 00 72 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 64 00 6c 00 6c 00 } //1 srclient.dll
		$a_01_2 = {52 00 43 00 5f 00 44 00 41 00 54 00 41 00 4d 00 41 00 4b 00 45 00 4d 00 4f 00 4e 00 45 00 59 00 } //1 RC_DATAMAKEMONEY
		$a_00_3 = {53 52 52 65 6d 6f 76 65 52 65 73 74 6f 72 65 50 6f 69 6e 74 } //1 SRRemoveRestorePoint
		$a_01_4 = {42 65 73 74 43 68 61 6e 67 65 54 30 70 4d 6f 6e 65 79 5e 5f 2d 36 36 36 } //1 BestChangeT0pMoney^_-666
		$a_01_5 = {42 65 73 74 43 68 61 6e 67 65 54 30 70 5e 5f 2d 36 36 36 } //1 BestChangeT0p^_-666
		$a_02_6 = {ff 2f c6 85 ?? ?? ?? ff 63 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 76 c6 85 ?? ?? ?? ff 73 c6 85 ?? ?? ?? ff 73 c6 85 ?? ?? ?? ff 61 c6 85 ?? ?? ?? ff 64 c6 85 ?? ?? ?? ff 6d c6 85 ?? ?? ?? ff 69 c6 85 ?? ?? ?? ff 6e c6 85 ?? ?? ?? ff 2e c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 78 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 44 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 74 c6 85 ?? ?? ?? ff 65 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 53 c6 85 ?? ?? ?? ff 68 c6 85 ?? ?? ?? ff 61 c6 85 ?? ?? ?? ff 64 c6 85 ?? ?? ?? ff 6f c6 85 ?? ?? ?? ff 77 c6 85 ?? ?? ?? ff 73 c6 85 ?? ?? ?? ff 20 c6 85 ?? ?? ?? ff 2f c6 85 ?? ?? ?? ff 41 c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 6c c6 85 ?? ?? ?? ff 20 } //10
		$a_02_7 = {0f b6 14 10 03 ca 81 e1 ff 00 00 00 8b 45 f8 0f b6 0c ?? 8b 55 08 03 55 ?? 0f b6 02 33 c1 8b 4d 08 03 4d ?? 88 01 e9 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_02_6  & 1)*10+(#a_02_7  & 1)*10) >=15
 
}