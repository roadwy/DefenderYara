
rule Trojan_Win32_NSISInject_FA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b f8 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 56 ff 15 } //10
		$a_03_1 = {83 c4 08 8b f0 6a 40 68 00 30 00 00 68 ?? ?? ?? ?? 57 ff 15 } //10
		$a_01_2 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*1) >=11
 
}