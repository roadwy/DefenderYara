
rule Trojan_Win32_Miser_C{
	meta:
		description = "Trojan:Win32/Miser.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 5c 8d 8d 60 ff ff ff 51 ff 15 90 01 02 40 00 6a 72 8d 95 50 ff ff ff 52 ff 15 90 01 02 40 00 6a 73 8d 85 30 ff ff ff 50 ff 15 90 01 02 40 00 6a 72 8d 8d 10 ff ff ff 51 ff 15 90 01 02 40 00 6a 6b 8d 95 f0 fe ff ff 52 ff 15 90 01 02 40 00 6a 5c 8d 85 d0 fe ff ff 50 ff 15 90 01 02 40 00 6a 32 8d 8d b0 fe ff ff 51 ff 15 90 01 02 40 00 6a 33 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}