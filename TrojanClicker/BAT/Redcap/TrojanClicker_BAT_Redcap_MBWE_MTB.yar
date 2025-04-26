
rule TrojanClicker_BAT_Redcap_MBWE_MTB{
	meta:
		description = "TrojanClicker:BAT/Redcap.MBWE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {44 65 6c 6c 2e 41 73 69 6d 6f 76 2e 49 6e 74 65 72 6f 70 } //1 Dell.Asimov.Interop
		$a_01_1 = {46 6f 72 6d 31 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } //1 Form1.Properties.Resources.resource
		$a_01_2 = {74 74 73 71 67 7a 68 6a 2e 65 78 65 } //2 ttsqgzhj.exe
		$a_01_3 = {45 33 44 35 43 30 43 33 33 30 43 32 } //2 E3D5C0C330C2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=6
 
}