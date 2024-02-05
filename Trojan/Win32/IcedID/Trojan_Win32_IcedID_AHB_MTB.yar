
rule Trojan_Win32_IcedID_AHB_MTB{
	meta:
		description = "Trojan:Win32/IcedID.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_80_0 = {65 63 63 63 5f 5f 5f 63 65 5f 73 5f 5f } //eccc___ce_s__  03 00 
		$a_80_1 = {65 66 65 68 6a 75 6e 6c 6f 70 6b 6a 75 } //efehjunlopkju  03 00 
		$a_80_2 = {62 73 69 74 6d 6a 61 73 64 6f } //bsitmjasdo  03 00 
		$a_80_3 = {69 73 65 75 73 62 72 73 61 6f 72 70 74 69 72 68 } //iseusbrsaorptirh  03 00 
		$a_80_4 = {46 69 6e 64 52 65 73 6f 75 72 63 65 57 } //FindResourceW  03 00 
		$a_80_5 = {4f 6c 65 46 6c 75 73 68 43 6c 69 70 62 6f 61 72 64 } //OleFlushClipboard  03 00 
		$a_80_6 = {43 6f 70 79 46 69 6c 65 41 } //CopyFileA  00 00 
	condition:
		any of ($a_*)
 
}