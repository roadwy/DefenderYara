
rule Trojan_Win32_Glupteba_GHX_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GHX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 1c 24 83 c4 04 01 f2 68 90 01 04 5a e8 90 01 04 21 f2 21 f6 31 18 40 29 f2 39 c8 75 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}