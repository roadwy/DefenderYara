
rule Backdoor_BAT_WebShell_GNF_MTB{
	meta:
		description = "Backdoor:BAT/WebShell.GNF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 16 11 06 8e 69 6f 90 01 03 0a 28 90 01 03 0a 6f 90 01 03 0a 00 02 6f 90 01 03 0a 6f 90 01 03 0a 08 1f 10 6f 90 01 03 0a 6f 90 01 03 0a 00 00 00 de 05 90 00 } //10
		$a_80_1 = {69 6d 61 67 65 73 2f 61 64 2f 69 6d 67 43 75 73 74 6f 6d 42 67 2e 61 73 70 78 } //images/ad/imgCustomBg.aspx  1
		$a_01_2 = {73 63 62 79 7a 68 5f 61 73 70 78 } //1 scbyzh_aspx
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}