
rule Trojan_Win32_MultiPlug_DSK_MTB{
	meta:
		description = "Trojan:Win32/MultiPlug.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 55 0b c0 65 0b 02 8a 45 0b 24 c0 0a c8 8a c2 c0 e0 06 80 e2 fc 88 45 0b 0a e8 8b 45 f0 c0 e2 04 0a d3 88 0c 06 88 54 06 01 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}