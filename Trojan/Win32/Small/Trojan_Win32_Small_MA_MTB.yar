
rule Trojan_Win32_Small_MA_MTB{
	meta:
		description = "Trojan:Win32/Small.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 c1 e6 12 ff 45 e4 c1 e0 0c 01 f0 8b 75 d4 c1 e6 06 01 f0 8b 75 e0 01 c8 89 c1 c1 e8 10 88 04 32 39 5d e4 73 28 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}