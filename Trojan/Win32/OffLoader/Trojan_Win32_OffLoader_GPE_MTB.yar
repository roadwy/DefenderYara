
rule Trojan_Win32_OffLoader_GPE_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.GPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 05 00 "
		
	strings :
		$a_80_0 = {64 75 63 6b 73 73 74 6f 70 2e 73 69 74 65 2f 67 6c 61 6d 2e 70 68 70 3f 70 65 } //ducksstop.site/glam.php?pe  02 00 
		$a_80_1 = {6a 65 6c 6c 79 66 69 73 68 74 72 65 65 73 2e 73 69 74 65 2f 74 72 61 63 6b 65 72 2f 74 68 61 6e 6b 5f 79 6f 75 2e 70 68 70 } //jellyfishtrees.site/tracker/thank_you.php  00 00 
	condition:
		any of ($a_*)
 
}