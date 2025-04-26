
rule Trojan_Win32_Neoreblamy_CB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 35 ?? ?? ?? ?? 8b 45 14 8b 40 04 0f b6 04 10 50 8b 45 } //3
		$a_03_1 = {8b 09 0f b6 04 01 50 e8 ?? ?? ?? ff 59 59 50 8d 4d } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}