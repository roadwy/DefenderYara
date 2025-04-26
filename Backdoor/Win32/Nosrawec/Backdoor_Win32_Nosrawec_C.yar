
rule Backdoor_Win32_Nosrawec_C{
	meta:
		description = "Backdoor:Win32/Nosrawec.C,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 06 00 00 "
		
	strings :
		$a_01_0 = {26 68 6c 3d 74 72 26 70 72 6d 64 3d 69 6c 62 26 73 74 61 72 74 3d } //2 &hl=tr&prmd=ilb&start=
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2e 74 72 2f 23 71 3d } //2 http://www.google.com.tr/#q=
		$a_01_2 = {70 68 70 3f 63 6f 6d 70 75 74 65 72 6e 61 6d 65 3d } //2 php?computername=
		$a_01_3 = {2e 65 78 65 63 } //1 .exec
		$a_01_4 = {2e 67 6f 67 6c } //1 .gogl
		$a_01_5 = {2e 64 64 6f 73 } //1 .ddos
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=7
 
}