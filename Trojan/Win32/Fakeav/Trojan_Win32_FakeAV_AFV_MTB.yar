
rule Trojan_Win32_FakeAV_AFV_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.AFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a d0 c0 c2 04 8a c2 24 0f bb 01 60 40 00 d7 a2 91 6b 40 00 c0 c2 04 8a c2 24 0f d7 a2 92 6b 40 00 } //3
		$a_03_1 = {ba 00 00 00 00 f7 f3 92 e8 ?? ?? ?? ?? 88 87 b0 67 40 00 4f 92 41 0b c0 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}