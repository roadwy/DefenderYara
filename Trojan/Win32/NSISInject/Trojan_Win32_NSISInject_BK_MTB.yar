
rule Trojan_Win32_NSISInject_BK_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 31 30 46 01 8d 76 03 b8 90 02 04 f7 e1 8b c3 83 c3 03 c1 ea 03 8d 0c 52 c1 e1 02 2b c1 0f b6 80 90 02 04 30 46 ff 81 fb d3 17 00 00 7c 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}