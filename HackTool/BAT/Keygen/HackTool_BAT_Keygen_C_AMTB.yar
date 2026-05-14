
rule HackTool_BAT_Keygen_C_AMTB{
	meta:
		description = "HackTool:BAT/Keygen.C!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4b 65 79 67 65 6e 20 66 6f 72 20 43 6f 6f 6c 77 61 72 65 4d 61 78 20 57 65 62 63 61 6d 4d 61 78 } //Keygen for CoolwareMax WebcamMax  1
		$a_80_1 = {5b 59 6f 75 72 20 63 6f 64 65 20 68 65 72 65 2e 2e 5d } //[Your code here..]  1
		$a_80_2 = {26 47 65 6e 65 72 61 74 65 } //&Generate  1
		$a_80_3 = {2e 3a 41 4d 50 45 44 3a 2e } //.:AMPED:.  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}