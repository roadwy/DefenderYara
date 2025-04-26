
rule Trojan_Win32_NSISInject_SPAB_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.SPAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 45 ff 0f b6 55 ff 2b 55 f4 88 55 ff 0f b6 45 ff f7 d8 88 45 ff 0f b6 4d ff 83 e9 37 88 4d ff 0f b6 55 ff 33 55 f4 88 55 ff 0f b6 45 ff 83 c0 17 88 45 ff 8b 4d e8 03 4d f4 8a 55 ff 88 11 e9 29 ff ff ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}