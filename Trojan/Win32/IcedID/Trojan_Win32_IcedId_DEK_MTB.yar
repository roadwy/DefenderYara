
rule Trojan_Win32_IcedId_DEK_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 90 01 04 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8d 4c 24 14 83 c5 01 0f b6 94 14 90 1b 00 30 55 ff 90 00 } //01 00 
		$a_81_1 = {6f 6e 49 74 72 4f 78 38 63 7a 39 33 5a 70 79 6b 66 4a 6c 42 61 59 54 44 5a 76 5a 59 56 66 48 52 51 6a 69 45 42 34 61 } //00 00 
	condition:
		any of ($a_*)
 
}