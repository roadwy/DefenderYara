
rule Trojan_Win32_Glupteba_DSF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DSF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {bb 87 d5 7c 3a 81 45 ?? 8c eb 73 22 8b } //1
		$a_02_1 = {c1 e9 05 03 8d ?? ?? ff ff 03 ?? ?? ?? ff ff 89 ?? ?? ?? ?? ?? 33 ?? 8b 8d ?? ?? ff ff 03 ?? 33 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}