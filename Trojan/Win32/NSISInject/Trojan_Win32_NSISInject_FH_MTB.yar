
rule Trojan_Win32_NSISInject_FH_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 04 68 00 30 00 00 68 80 74 d2 1a 57 ff d6 } //10
		$a_03_1 = {88 04 3e 47 3b fb 72 ?? 6a 00 56 ff 15 ?? ?? ?? ?? 81 e9 14 c4 00 00 c2 2b 20 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}