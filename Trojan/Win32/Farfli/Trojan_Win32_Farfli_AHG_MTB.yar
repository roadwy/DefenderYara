
rule Trojan_Win32_Farfli_AHG_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 ec 8b 48 08 8b 45 14 0f b6 04 ?? 99 ?? 15 18 00 00 f7 ?? 8b c6 6a 0a 80 c2 3d 30 14 31 99 59 f7 f9 ?? 85 d2 75 } //5
		$a_03_1 = {6a 04 68 00 10 00 00 53 6a 00 ff 15 ?? ?? ?? 00 8b ce 8b f8 e8 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}