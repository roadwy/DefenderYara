
rule Trojan_Win32_Glupteba_GZK_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {bf d8 85 40 00 21 c1 e8 ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 48 31 3b 01 c8 43 39 f3 75 e4 41 c3 21 c9 8d 3c 17 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}