
rule VirTool_Win32_VBInject_HM{
	meta:
		description = "VirTool:Win32/VBInject.HM,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 4d 00 69 00 73 00 20 00 43 00 6f 00 73 00 61 00 73 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 61 00 63 00 69 00 6f 00 6e 00 5c 00 56 00 69 00 73 00 75 00 61 00 6c 00 20 00 42 00 61 00 73 00 69 00 63 00 20 00 36 00 5c 00 4d 00 69 00 73 00 20 00 53 00 6f 00 75 00 72 00 63 00 65 00 73 00 5c 00 4b 00 78 00 2d 00 43 00 72 00 79 00 70 00 74 00 65 00 } //1 C:\Mis Cosas\Programacion\Visual Basic 6\Mis Sources\Kx-Crypte
		$a_01_1 = {53 00 43 00 5c 00 53 00 74 00 75 00 62 00 5c 00 50 00 72 00 6f 00 79 00 65 00 63 00 74 00 6f 00 31 00 2e 00 76 00 62 00 70 00 } //1 SC\Stub\Proyecto1.vbp
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}