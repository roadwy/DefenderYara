
rule Trojan_Win32_Offloader_KAA_MTB{
	meta:
		description = "Trojan:Win32/Offloader.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 73 69 6e 6b 6c 69 6e 65 2e 78 79 7a 2f 6c 6d 6b 2e 70 68 70 } //://sinkline.xyz/lmk.php  02 00 
		$a_80_1 = {3a 2f 2f 73 61 76 65 2e 77 69 6e 64 6f 77 73 74 6f 6e 65 2e 77 65 62 73 69 74 65 } //://save.windowstone.website  01 00 
		$a_80_2 = {53 6f 66 74 77 61 72 65 5c 53 50 6f 6c 6f 43 6c 65 61 6e 65 72 } //Software\SPoloCleaner  00 00 
	condition:
		any of ($a_*)
 
}