
rule Trojan_Win32_DanaBot_GJ_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 18 88 10 88 1e 0f b6 00 0f b6 d3 03 c2 23 c1 [0-25] 8a 80 [0-30] 33 cd } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}