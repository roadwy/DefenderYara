
rule Trojan_Win32_Glupteba_UI_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.UI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 74 01 ea 31 1e b9 90 01 04 81 ef 90 01 04 81 c6 90 01 04 4a 39 c6 75 90 01 01 81 c1 90 01 04 81 ef 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}