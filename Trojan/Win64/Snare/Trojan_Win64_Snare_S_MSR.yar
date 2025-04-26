
rule Trojan_Win64_Snare_S_MSR{
	meta:
		description = "Trojan:Win64/Snare.S!MSR,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 00 53 00 48 00 4d 00 44 00 52 00 } //1 CSHMDR
		$a_01_1 = {4f 33 64 4a 78 62 4f 59 64 33 59 32 52 68 51 4a 4f 49 4a 2f 64 30 72 3d } //1 O3dJxbOYd3Y2RhQJOIJ/d0r=
		$a_01_2 = {41 4e 4f 4e 59 4d 4f 55 53 20 4c 4f 47 4f 4e } //1 ANONYMOUS LOGON
		$a_01_3 = {61 00 74 00 6c 00 54 00 72 00 61 00 63 00 65 00 43 00 4f 00 4d 00 } //1 atlTraceCOM
		$a_01_4 = {61 00 74 00 6c 00 54 00 72 00 61 00 63 00 65 00 57 00 69 00 6e 00 64 00 6f 00 77 00 69 00 6e 00 67 00 } //1 atlTraceWindowing
		$a_01_5 = {4e 65 74 55 73 65 72 47 65 74 49 6e 66 6f } //1 NetUserGetInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}