
rule Virus_Linux_Marker_AH{
	meta:
		description = "Virus:Linux/Marker.AH,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {63 6f 64 65 6d 6f 64 75 6c 65 2e 46 69 6e 64 28 22 6e 69 61 68 69 79 69 67 65 62 65 6e 64 61 6e 22 } //1 codemodule.Find("niahiyigebendan"
		$a_00_1 = {53 68 65 6c 6c 20 28 22 5c 5c 6a 64 71 5c 63 63 24 5c 62 2e 65 78 65 22 29 } //1 Shell ("\\jdq\cc$\b.exe")
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}