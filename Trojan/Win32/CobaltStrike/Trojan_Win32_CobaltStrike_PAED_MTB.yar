
rule Trojan_Win32_CobaltStrike_PAED_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.PAED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 01 39 cb 7e 78 48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 02 39 cb 7e 62 48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 03 } //1
		$a_01_1 = {48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 04 39 cb 7e 36 48 63 c9 44 0f b6 04 0e 41 31 f8 44 88 04 0a 8d 48 05 39 cb 7e 20 48 63 c9 83 c0 06 44 0f b6 04 0e 41 31 f8 44 88 04 0a 39 c3 7e 0a 48 98 40 32 3c 06 40 88 3c 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}