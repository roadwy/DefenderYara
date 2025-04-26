
rule Trojan_BAT_Nanocore_NH_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 0a 00 00 0a 0a 06 74 16 00 00 01 73 0b 00 00 0a 0b 17 13 04 2b bf 07 74 19 00 00 01 02 7b 04 00 00 04 20 b8 03 00 00 20 98 03 00 00 28 05 00 00 2b 20 0f 03 00 00 20 40 03 00 00 28 } //3
		$a_01_1 = {73 5a 49 70 2e 65 78 65 } //1 sZIp.exe
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}