
rule Trojan_Win32_NSISInject_NW_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.NW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c4 08 89 45 ec 6a 40 68 00 30 00 00 8b 4d f4 51 6a 00 ff 15 24 20 40 00 } //1
		$a_01_1 = {52 6a 01 8b 45 f4 50 8b 4d f8 51 ff 15 30 20 40 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}