
rule Trojan_Win32_OffLoader_GDAA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {3a 00 2f 00 2f 00 74 00 6f 00 77 00 6e 00 64 00 75 00 73 00 74 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 61 00 66 00 2e 00 70 00 68 00 70 00 3f 00 } //02 00  ://towndust.website/af.php?
		$a_01_1 = {3a 00 2f 00 2f 00 65 00 64 00 75 00 63 00 61 00 74 00 69 00 6f 00 6e 00 63 00 6f 00 61 00 63 00 68 00 2e 00 73 00 69 00 74 00 65 00 2f 00 61 00 66 00 74 00 2e 00 70 00 68 00 70 00 3f 00 } //02 00  ://educationcoach.site/aft.php?
		$a_01_2 = {3a 00 2f 00 2f 00 76 00 6f 00 79 00 61 00 67 00 65 00 62 00 6c 00 6f 00 6f 00 64 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 67 00 6c 00 61 00 6d 00 2e 00 70 00 68 00 70 00 3f 00 } //02 00  ://voyageblood.online/glam.php?
		$a_01_3 = {3a 00 2f 00 2f 00 73 00 65 00 72 00 76 00 61 00 6e 00 74 00 7a 00 65 00 70 00 68 00 79 00 72 00 2e 00 6f 00 6e 00 6c 00 69 00 6e 00 65 00 2f 00 74 00 72 00 61 00 63 00 6b 00 65 00 72 00 2f 00 74 00 68 00 61 00 6e 00 6b 00 5f 00 79 00 6f 00 75 00 2e 00 70 00 68 00 70 00 3f 00 } //01 00  ://servantzephyr.online/tracker/thank_you.php?
		$a_01_4 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //00 00  /silent
	condition:
		any of ($a_*)
 
}