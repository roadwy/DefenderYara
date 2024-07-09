
rule Trojan_Win32_Glupteba_GMQ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GMQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 81 c7 ?? ?? ?? ?? 81 c2 04 00 00 00 39 f2 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}