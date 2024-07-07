
rule Trojan_Win32_NSISInject_DF_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.DF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 45 fc 00 00 00 00 6a 04 68 00 30 00 00 68 00 a3 e1 11 6a 00 ff 15 } //5
		$a_03_1 = {c1 fa 03 0f b6 05 90 01 04 c1 e0 05 0b d0 88 15 90 01 04 0f b6 0d 90 09 1f 00 a2 90 01 04 0f b6 0d 90 01 04 33 0d 90 01 04 88 0d 90 01 04 0f b6 15 90 00 } //1
		$a_03_2 = {c1 fa 06 0f b6 05 90 01 04 c1 e0 02 0b d0 88 15 90 01 04 0f b6 0d 90 09 1f 00 a2 90 01 04 0f b6 0d 90 01 04 2b 0d 90 01 04 88 0d 90 01 04 0f b6 15 90 00 } //1
		$a_03_3 = {c1 f8 07 0f b6 0d 90 01 04 d1 e1 0b c1 a2 90 01 04 8b 15 90 09 1f 00 a2 90 01 04 0f b6 15 90 01 04 2b 15 90 01 04 88 15 90 01 04 0f b6 05 90 00 } //1
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}