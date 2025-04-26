
rule Trojan_Win32_Glupteba_AD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 3a 42 39 da 75 ec c3 8d 3c 37 8b 3f 40 09 c9 81 e7 ?? ?? ?? ?? 29 c0 81 c6 ?? ?? ?? ?? 40 81 fe } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}