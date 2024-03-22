
rule Trojan_Win32_OffLoader_GPC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_80_0 = {77 61 73 74 65 74 6f 70 2e 77 65 62 73 69 74 65 2f 72 75 6e 2e 70 68 70 } //wastetop.website/run.php  02 00 
		$a_80_1 = {74 68 6f 75 67 68 74 6d 65 61 6c 2e 73 69 74 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 } //thoughtmeal.site/tracker/thank_you  00 00 
	condition:
		any of ($a_*)
 
}