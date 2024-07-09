
rule Worm_Win32_Culler_R{
	meta:
		description = "Worm:Win32/Culler.R,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 53 79 73 41 72 63 2e 65 78 65 } //1 \SysArc.exe
		$a_00_1 = {6d 69 72 61 20 65 73 74 61 20 61 6e 69 6d 61 63 69 6f 6e 20 64 65 20 62 75 73 68 20 3a 50 } //1 mira esta animacion de bush :P
		$a_00_2 = {4d 65 6e 73 61 67 65 20 61 20 74 6f 64 6f 73 } //1 Mensage a todos
		$a_00_3 = {44 69 72 65 63 74 6f 72 69 6f 73 20 64 65 6c 20 73 69 73 74 65 6d 61 } //1 Directorios del sistema
		$a_02_4 = {c7 45 fc 0c 00 00 00 6a 01 8b 55 08 8b 02 8b 4d 08 51 ff 90 90 ?? 07 00 00 c7 45 fc 0d 00 00 00 c7 45 bc 04 00 02 80 c7 45 b4 0a 00 00 00 8d 55 b4 52 68 ?? ?? 40 00 ff 15 ?? 10 40 00 8d 4d b4 ff 15 ?? 10 40 00 c7 45 fc 0e 00 00 00 c7 45 bc 04 00 02 80 c7 45 b4 0a 00 00 00 8d 45 b4 50 68 ?? ?? 40 00 ff 15 ?? 10 40 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}