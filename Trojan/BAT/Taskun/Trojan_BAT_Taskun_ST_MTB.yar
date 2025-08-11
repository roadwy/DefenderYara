
rule Trojan_BAT_Taskun_ST_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 72 c5 05 00 70 a2 25 17 12 45 28 2b 00 00 0a a2 25 18 72 00 0a 00 70 a2 25 19 12 31 28 2b 00 00 0a a2 25 1a 72 00 0a 00 70 a2 25 1b 12 34 28 2b 00 00 0a a2 28 35 00 00 0a 13 0a 11 45 17 58 13 45 11 45 11 41 32 9c } //2
		$a_01_1 = {42 61 63 6b 45 6e 64 4c 69 62 72 61 72 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 BackEndLibrary.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}