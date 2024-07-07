
rule Trojan_Win32_Emotet_PDV_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8a 03 8d 4c 24 90 01 01 c7 84 24 90 01 04 ff ff ff ff 8a 94 14 90 01 04 32 c2 88 03 90 09 05 00 b9 90 00 } //1
		$a_81_1 = {56 51 6f 68 47 54 58 4c 31 73 58 6f 33 38 77 77 6b 49 32 46 38 75 70 4e 7a 72 49 58 70 45 33 6a 78 69 } //1 VQohGTXL1sXo38wwkI2F8upNzrIXpE3jxi
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}