
rule Trojan_Win32_Copak_BAG_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {01 c9 31 1a 89 c1 b9 c4 01 20 5a 42 81 e8 01 00 00 00 01 c9 39 f2 75 } //2
		$a_01_1 = {5a 81 c3 f0 87 c6 7d 89 f3 81 c7 01 00 00 00 81 ee 20 f6 88 bc 21 f6 09 db 81 ff 5c 00 00 01 75 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}