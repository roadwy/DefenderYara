
rule Trojan_Win32_NSISInject_MBAL_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.MBAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 10 03 c1 89 45 f4 8b c1 99 6a 0c 5f f7 ff 8b 7d f4 8a 82 ?? ?? ?? ?? 30 07 41 3b cb 72 e0 } //1
		$a_01_1 = {83 c4 24 6a 40 68 00 30 00 00 53 56 ff 55 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}