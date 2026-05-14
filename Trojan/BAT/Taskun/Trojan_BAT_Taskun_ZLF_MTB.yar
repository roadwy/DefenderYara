
rule Trojan_BAT_Taskun_ZLF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZLF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 02 00 00 "
		
	strings :
		$a_03_0 = {26 38 17 ff ff ff 04 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 11 09 } //10
		$a_80_1 = {47 65 74 50 69 78 65 6c } //GetPixel  2
	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*2) >=12
 
}