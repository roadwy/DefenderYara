
rule Trojan_Win32_Vidar_PAB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b8 cd cc cc cc f7 e1 8b c1 c1 ea 03 8d 14 92 03 d2 2b c2 8d 96 10 76 4b 00 03 d1 0f b6 80 00 30 41 00 30 81 10 76 4b 00 b8 cd cc cc cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}