
rule Trojan_O97M_Obfuse_SC_MTB{
	meta:
		description = "Trojan:O97M/Obfuse.SC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 22 25 63 6f 6d 73 70 65 63 25 2f 63 73 74 61 72 74 2f 77 61 69 74 63 3a 5c [0-15] 5c [0-15] 2e 76 62 73 } //2
		$a_02_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 22 72 65 67 73 76 72 33 32 2e 65 78 65 2d 73 63 3a 5c [0-15] 5c [0-15] 2e 64 6c 6c } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}
rule Trojan_O97M_Obfuse_SC_MTB_2{
	meta:
		description = "Trojan:O97M/Obfuse.SC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 22 25 63 6f 6d 73 70 65 63 25 2f 63 73 74 61 72 74 2f 77 61 69 74 63 3a 5c 67 6f 70 68 6f 74 6f 6e 69 63 73 5c 72 65 64 64 69 74 2e 76 62 73 } //2 createobject("wscript.shell").exec"%comspec%/cstart/waitc:\gophotonics\reddit.vbs
		$a_00_1 = {63 72 65 61 74 65 6f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 22 72 65 67 73 76 72 33 32 2e 65 78 65 2d 73 63 3a 5c 67 6f 70 68 6f 74 6f 6e 69 63 73 5c 77 61 76 65 70 6c 61 74 65 2e 64 6c 6c } //1 createobject("wscript.shell").exec"regsvr32.exe-sc:\gophotonics\waveplate.dll
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}