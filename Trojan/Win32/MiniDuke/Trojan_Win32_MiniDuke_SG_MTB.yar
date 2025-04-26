
rule Trojan_Win32_MiniDuke_SG_MTB{
	meta:
		description = "Trojan:Win32/MiniDuke.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 0d 18 30 40 00 09 c9 74 11 a1 10 30 40 00 8d 0c 88 51 50 e8 b5 ff ff ff 59 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}