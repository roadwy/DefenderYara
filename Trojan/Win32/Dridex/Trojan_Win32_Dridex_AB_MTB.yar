
rule Trojan_Win32_Dridex_AB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AB!MTB,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 04 4a 89 7d c4 8d 56 f9 03 55 d0 81 c7 ed 1e 00 00 03 c7 8d be 8b 1e ff ff 0f b7 c8 8b c6 83 c0 f3 03 45 d0 03 c1 2b c8 8b c6 03 45 d0 03 ce 69 c0 38 f9 00 00 8d 0c c9 c1 e1 02 2b c8 8d 86 29 d0 06 00 2b ca 8b 55 d0 03 4d c4 03 c1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}