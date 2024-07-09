
rule Trojan_BAT_Redline_GJZ_MTB{
	meta:
		description = "Trojan:BAT/Redline.GJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 07 1d 2d 58 26 26 26 7e ?? ?? ?? ?? 06 18 28 ?? ?? ?? 06 7e ?? ?? ?? ?? 06 19 28 ?? ?? ?? 06 7e ?? ?? ?? ?? 06 28 ?? ?? ?? 06 0d 7e ?? ?? ?? ?? 09 03 16 03 8e 69 } //10
		$a_01_1 = {6e 68 66 66 73 6b 64 67 73 66 6b 64 66 66 64 64 61 64 66 72 66 66 66 66 64 68 66 66 73 63 66 64 66 } //1 nhffskdgsfkdffddadfrffffdhffscfdf
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}