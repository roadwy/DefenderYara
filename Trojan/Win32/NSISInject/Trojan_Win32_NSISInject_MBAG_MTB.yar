
rule Trojan_Win32_NSISInject_MBAG_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.MBAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 e6 c1 ea 03 8b c6 8d 0c 52 c1 e1 02 2b c1 46 8a 80 ?? ?? ?? ?? 30 44 1e ff 3b f7 72 dd } //1
		$a_01_1 = {83 c4 24 6a 40 68 00 30 00 00 57 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}