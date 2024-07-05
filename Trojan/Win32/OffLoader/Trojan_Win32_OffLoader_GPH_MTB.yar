
rule Trojan_Win32_OffLoader_GPH_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_80_0 = {66 6f 72 6b 63 61 73 74 2e 77 65 62 73 69 74 65 2f 61 72 74 2e 70 68 70 3f 70 69 64 } //forkcast.website/art.php?pid  02 00 
		$a_80_1 = {66 6f 72 6b 63 61 73 74 2e 77 65 62 73 69 74 65 2f 72 6c 6f 2e 70 68 70 } //forkcast.website/rlo.php  00 00 
	condition:
		any of ($a_*)
 
}