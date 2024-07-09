
rule Trojan_Win32_Glupteba_UL_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.UL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 01 d7 01 ea 31 33 81 c3 ?? ?? ?? ?? b9 ?? ?? ?? ?? 39 c3 75 ea c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}