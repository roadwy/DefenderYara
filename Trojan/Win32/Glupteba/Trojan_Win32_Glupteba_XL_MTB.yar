
rule Trojan_Win32_Glupteba_XL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.XL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 16 09 d9 81 c6 ?? ?? ?? ?? 01 c9 41 39 fe 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}