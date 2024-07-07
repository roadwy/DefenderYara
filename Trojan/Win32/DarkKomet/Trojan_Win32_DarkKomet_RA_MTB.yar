
rule Trojan_Win32_DarkKomet_RA_MTB{
	meta:
		description = "Trojan:Win32/DarkKomet.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 64 00 6f 00 72 00 5c 00 45 00 73 00 63 00 72 00 69 00 74 00 6f 00 72 00 69 00 6f 00 5c 00 53 00 55 00 50 00 45 00 52 00 5c 00 53 00 54 00 55 00 42 00 5c 00 6f 00 6c 00 61 00 6c 00 61 00 6c 00 61 00 6c 00 6c 00 61 00 6c 00 61 00 6c 00 61 00 6c 00 2e 00 76 00 62 00 70 00 } //1 Administrador\Escritorio\SUPER\STUB\olalalallalalal.vbp
		$a_01_1 = {45 73 63 72 69 74 6f 72 69 6f 5c 54 4d 2e 65 78 65 } //1 Escritorio\TM.exe
		$a_01_2 = {41 72 63 68 69 76 6f 73 20 64 65 20 70 72 6f 67 72 61 6d 61 5c 4e 54 43 6f 72 65 5c 45 78 70 6c 6f 72 65 72 20 53 75 69 74 65 5c 45 78 74 65 6e 73 69 6f 6e 73 5c 43 46 46 20 45 78 70 6c 6f 72 65 72 } //1 Archivos de programa\NTCore\Explorer Suite\Extensions\CFF Explorer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}