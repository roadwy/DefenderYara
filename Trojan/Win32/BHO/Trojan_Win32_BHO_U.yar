
rule Trojan_Win32_BHO_U{
	meta:
		description = "Trojan:Win32/BHO.U,SIGNATURE_TYPE_PEHSTR_EXT,3d 00 3d 00 08 00 00 "
		
	strings :
		$a_00_0 = {38 00 30 00 45 00 46 00 33 00 30 00 34 00 41 00 2d 00 42 00 31 00 43 00 34 00 2d 00 34 00 32 00 35 00 43 00 2d 00 38 00 35 00 33 00 35 00 2d 00 39 00 35 00 41 00 42 00 36 00 46 00 31 00 45 00 45 00 46 00 42 00 38 00 } //10 80EF304A-B1C4-425C-8535-95AB6F1EEFB8
		$a_00_1 = {73 00 74 00 61 00 72 00 74 00 3d 00 30 00 00 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e } //10
		$a_00_2 = {48 00 41 00 52 00 44 00 57 00 41 00 52 00 45 00 5c 00 44 00 45 00 53 00 43 00 52 00 49 00 50 00 54 00 49 00 4f 00 4e 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 65 00 6e 00 74 00 72 00 61 00 6c 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 6f 00 72 00 5c 00 30 00 } //10 HARDWARE\DESCRIPTION\System\CentralProcessor\0
		$a_00_3 = {3c 00 61 00 20 00 63 00 6c 00 61 00 73 00 73 00 3d 00 79 00 73 00 63 00 68 00 74 00 74 00 6c 00 20 00 68 00 72 00 65 00 66 00 3d 00 } //10 <a class=yschttl href=
		$a_00_4 = {72 00 65 00 73 00 75 00 6c 00 74 00 73 00 2f 00 72 00 6f 00 75 00 74 00 65 00 72 00 } //10 results/router
		$a_00_5 = {72 00 65 00 73 00 75 00 6c 00 74 00 73 00 2f 00 70 00 6f 00 70 00 } //10 results/pop
		$a_01_6 = {42 48 4f 5f 4d 79 4a 61 76 61 43 6f 72 65 2e 44 4c 4c } //1 BHO_MyJavaCore.DLL
		$a_01_7 = {4d 4a 43 6f 72 65 2e 44 4c 4c } //1 MJCore.DLL
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=61
 
}