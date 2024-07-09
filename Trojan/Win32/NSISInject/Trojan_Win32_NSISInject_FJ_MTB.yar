
rule Trojan_Win32_NSISInject_FJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 45 ff 33 45 f8 88 45 ff 0f b6 45 ff } //1
		$a_01_1 = {68 00 a3 e1 11 68 de 00 00 00 ff 75 f4 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_NSISInject_FJ_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.FJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 0c 6a 40 68 00 30 00 00 68 49 13 00 00 57 ff 15 } //10
		$a_03_1 = {88 04 3e 47 3b fb 72 ?? 6a 00 56 ff 15 ?? ?? ?? ?? 5f 5e 33 c0 5b 8b e5 5d c3 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}