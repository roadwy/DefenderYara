
rule TrojanDropper_Win32_Bohu_A{
	meta:
		description = "TrojanDropper:Win32/Bohu.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 63 20 6e 65 74 73 68 20 2d 63 20 69 6e 74 65 72 66 61 63 65 20 64 75 6d 70 3e } //1 /c netsh -c interface dump>
		$a_00_1 = {6e 65 74 73 68 20 69 6e 74 65 72 66 61 63 65 20 69 70 20 73 65 74 20 61 64 64 72 65 73 73 20 6e 61 6d 65 3d 22 fd a6 80 22 20 20 73 6f 75 72 63 65 3d 64 68 63 70 } //1
		$a_02_2 = {2f 54 49 4d 45 4f 55 54 3d ?? 30 30 30 30 00 45 78 65 63 54 6f 4c 6f 67 00 ?? 30 30 30 00 73 6f 75 72 63 65 3d 73 74 61 74 69 63 } //1
		$a_00_3 = {73 76 72 2e 61 73 70 3f 74 3d 75 75 70 6c 61 79 26 75 3d } //1 svr.asp?t=uuplay&u=
		$a_00_4 = {6d 73 66 73 67 2e 65 78 65 20 75 6e 63 6f 6d 70 72 65 73 73 20 2d 73 } //1 msfsg.exe uncompress -s
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}