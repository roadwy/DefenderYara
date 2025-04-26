
rule Trojan_Win32_Glupteba_GMX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 1f 81 c6 ?? ?? ?? ?? 81 c7 04 00 00 00 39 d7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}