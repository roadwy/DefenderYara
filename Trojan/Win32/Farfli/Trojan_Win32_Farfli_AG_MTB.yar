
rule Trojan_Win32_Farfli_AG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 3c 11 8b 55 08 0f b6 04 02 99 bb ?? ?? ?? 00 f7 fb ff 45 08 b8 cd ?? ?? ?? 80 c2 36 30 17 f7 e1 c1 ea 03 8d 04 92 03 c0 8b d1 2b d0 75 03 89 55 08 8b 45 0c 41 3b c8 7c } //3
		$a_03_1 = {6a 00 6a 00 ff 15 ?? ?? ?? ?? 6a ff 50 ff 15 ?? ?? ?? ?? 68 2c 01 00 00 ff 15 ?? ?? ?? ?? 32 c0 c3 cc } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}