
rule Trojan_Win32_Razy_GV_MTB{
	meta:
		description = "Trojan:Win32/Razy.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 31 19 41 09 f2 39 c1 75 ec 21 d2 c3 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}