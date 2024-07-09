
rule Trojan_Win32_Glupteba_GHJ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 03 09 c9 81 e9 ?? ?? ?? ?? 81 c3 04 00 00 00 47 01 f9 39 f3 75 e4 21 cf 01 d2 c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}