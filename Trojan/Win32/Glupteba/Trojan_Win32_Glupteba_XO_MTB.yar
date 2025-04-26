
rule Trojan_Win32_Glupteba_XO_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.XO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 ea 31 0f 81 ea ?? ?? ?? ?? be ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 09 d2 39 c7 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}