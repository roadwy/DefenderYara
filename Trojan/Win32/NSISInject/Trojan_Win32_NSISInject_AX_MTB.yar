
rule Trojan_Win32_NSISInject_AX_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {56 8b 75 10 6a 01 8b d8 56 53 e8 [0-04] 83 c4 10 85 f6 74 } //2
		$a_03_1 = {8b c7 99 6a 0c 59 f7 f9 8a 82 [0-04] 30 04 1f 47 3b fe 72 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}