
rule Trojan_O97M_Iscodtas_CO_MTB{
	meta:
		description = "Trojan:O97M/Iscodtas.CO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 WScript.Shell
		$a_00_1 = {25 61 70 70 64 61 74 61 25 5c } //1 %appdata%\
		$a_00_2 = {73 63 68 74 61 73 6b 73 20 2f 43 72 65 61 74 65 } //1 schtasks /Create
		$a_00_3 = {2e 72 75 6e 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 74 69 6d 65 6f 75 74 } //1 .run("cmd.exe /c timeout
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}