
rule Trojan_Win32_Zapchast_AB_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c1 f7 b5 f8 fe ff ff 0f b6 9c 0d fc fe ff ff 41 0f b6 14 3a 03 d3 03 f2 81 e6 ff 00 00 00 8a 84 35 fc fe ff ff 88 84 0d fb fe ff ff 88 9c 35 fc fe ff ff 81 f9 00 01 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}