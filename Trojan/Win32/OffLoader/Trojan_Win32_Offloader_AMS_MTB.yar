
rule Trojan_Win32_Offloader_AMS_MTB{
	meta:
		description = "Trojan:Win32/Offloader.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 76 6f 69 63 65 63 61 72 72 69 61 67 65 2e 77 65 62 73 69 74 65 2f 6b 61 6d 2e 70 68 70 } //http://voicecarriage.website/kam.php  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1) >=5
 
}