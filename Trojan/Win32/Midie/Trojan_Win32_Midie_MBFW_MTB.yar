
rule Trojan_Win32_Midie_MBFW_MTB{
	meta:
		description = "Trojan:Win32/Midie.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 33 c0 21 45 ec 88 45 ff 40 8b 7d 08 8b f0 89 45 f4 b9 9b 83 01 00 89 45 f8 33 db } //01 00 
		$a_01_1 = {5f 63 67 6f 5f 64 75 6d 6d 79 5f 65 78 70 6f 72 74 00 6d 69 6b 79 2e 64 } //00 00  损潧摟浵祭敟灸牯t業祫搮
	condition:
		any of ($a_*)
 
}