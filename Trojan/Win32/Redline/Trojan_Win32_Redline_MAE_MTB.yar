
rule Trojan_Win32_Redline_MAE_MTB{
	meta:
		description = "Trojan:Win32/Redline.MAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 0c 81 8b 44 24 ?? 8a 04 01 8d 4c ?? 24 30 06 } //1
		$a_03_1 = {47 89 7c 24 ?? 3b bc 24 ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}