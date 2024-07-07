
rule Trojan_Win32_NSISInject_SIBA_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 6e 00 61 00 6d 00 65 00 20 00 75 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 3e 00 } //1 <program name unknown>
		$a_03_1 = {88 0a 8b 45 90 01 01 03 45 90 01 01 8a 08 80 c1 90 01 01 8b 55 90 1b 00 03 55 90 1b 01 88 0a 90 00 } //1
		$a_03_2 = {88 0a 8b 45 90 01 01 03 45 90 01 01 0f b6 08 83 f1 90 01 01 8b 55 90 1b 00 03 55 90 1b 01 88 0a 90 00 } //1
		$a_03_3 = {88 0a 8b 45 90 01 01 03 45 90 01 01 0f b6 08 81 e9 90 01 04 8b 55 90 1b 00 03 55 90 1b 01 88 0a 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}