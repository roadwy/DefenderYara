
rule Trojan_Win32_Glupteba_XK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.XK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 1a 81 c2 04 00 00 00 39 c2 ?? ?? b9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}