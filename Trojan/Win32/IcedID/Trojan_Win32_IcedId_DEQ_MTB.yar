
rule Trojan_Win32_IcedId_DEQ_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 01 6a 00 6a 00 8d 55 90 01 01 52 ff 15 90 01 04 85 c0 75 40 6a 08 6a 01 6a 00 6a 00 8d 45 90 1b 00 50 ff 15 90 1b 01 85 c0 90 00 } //01 00 
		$a_81_1 = {58 64 71 37 6d 6b 35 69 4e 53 70 32 65 57 46 } //00 00  Xdq7mk5iNSp2eWF
	condition:
		any of ($a_*)
 
}