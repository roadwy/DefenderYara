
rule Trojan_Win32_FormBook_MBAM_MTB{
	meta:
		description = "Trojan:Win32/FormBook.MBAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 99 b9 0c 00 00 00 f7 f9 8b 45 b8 0f b6 0c 10 8b 55 f0 03 55 f4 0f b6 02 33 c1 8b 4d f0 03 4d f4 88 01 } //01 00 
		$a_01_1 = {6a 00 8b 4d ec 51 e8 cb 8f 00 00 83 c4 0c 6a 40 68 00 30 00 00 8b 55 e8 52 6a 00 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}