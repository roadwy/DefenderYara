
rule Trojan_Win32_Glupteba_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d9 09 c9 e8 ?? ?? ?? ?? 31 3a 53 5b 42 81 eb ?? ?? ?? ?? 29 cb 39 c2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}