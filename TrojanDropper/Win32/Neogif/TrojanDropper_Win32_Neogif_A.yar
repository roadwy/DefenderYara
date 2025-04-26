
rule TrojanDropper_Win32_Neogif_A{
	meta:
		description = "TrojanDropper:Win32/Neogif.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 34 71 74 72 73 7a 35 62 66 6e 33 6f 31 67 } //2 m4qtrsz5bfn3o1g
		$a_01_1 = {2f 68 2e 67 69 66 3f 70 69 64 20 3d 31 31 33 26 76 3d 31 33 30 35 38 36 32 31 34 35 36 38 20 48 54 54 50 2f 31 2e 31 } //2 /h.gif?pid =113&v=130586214568 HTTP/1.1
		$a_01_2 = {25 73 6b 62 64 6d 67 72 2e 6c 6e 6b } //2 %skbdmgr.lnk
		$a_01_3 = {25 73 6b 62 64 6d 67 72 2e 65 78 65 } //2 %skbdmgr.exe
		$a_01_4 = {53 65 72 76 65 72 7a 2e 64 6c 6c } //1 Serverz.dll
		$a_01_5 = {32 31 30 2e 32 30 39 2e 31 31 38 2e 38 37 } //1 210.209.118.87
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}