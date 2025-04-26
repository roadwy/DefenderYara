
rule Trojan_Win32_NjRAT_A_MTB{
	meta:
		description = "Trojan:Win32/NjRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {f5 00 00 00 00 f5 80 00 00 00 6c 0c 00 4d 50 ff 08 40 04 ?? ff 0a 00 00 10 00 04 ?? ff fc 60 3c } //4
		$a_01_1 = {f5 00 00 00 00 f5 ff ff ff ff f5 01 00 00 00 f5 00 00 00 00 1b 04 00 80 0c } //2
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}