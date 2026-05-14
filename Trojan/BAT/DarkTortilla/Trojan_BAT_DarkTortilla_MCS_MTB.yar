
rule Trojan_BAT_DarkTortilla_MCS_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.MCS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_1 = {61 62 69 73 65 72 2e 64 6c 6c } //1 abiser.dll
		$a_01_2 = {42 6f 67 61 72 69 6e 61 62 69 73 65 72 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 } //2 Bogarinabiser.My.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=4
 
}