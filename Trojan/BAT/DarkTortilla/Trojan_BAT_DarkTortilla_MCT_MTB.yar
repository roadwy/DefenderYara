
rule Trojan_BAT_DarkTortilla_MCT_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MCT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 58 45 73 50 41 43 4c 61 62 36 54 4e 73 4e 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 AXEsPACLab6TNsN.g.resources
		$a_01_1 = {6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 lSfgApatkdxsVcGcrktoFd.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}