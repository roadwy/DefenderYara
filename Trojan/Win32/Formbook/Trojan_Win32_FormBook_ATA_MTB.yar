
rule Trojan_Win32_FormBook_ATA_MTB{
	meta:
		description = "Trojan:Win32/FormBook.ATA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {51 53 50 56 ff 15 ?? ?? ?? ?? 8b 4d 10 8a 04 39 2c 2d 34 40 04 0c 34 b8 fe c8 88 04 39 47 3b fb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}